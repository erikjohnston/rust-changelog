extern crate reqwest;
extern crate git2;
extern crate regex;
extern crate hyper;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate serde_derive;
extern crate indicatif;
extern crate scoped_pool;


use hyper::header::{Authorization, Bearer};
use indicatif::ProgressBar;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};



quick_error! {
    #[derive(Debug)]
    pub enum Error {
        GitError(err: git2::Error) {
            from()
            description("git error")
            display("Git error: {}", err)
            cause(err)
        }
        ReqwestError(err: reqwest::Error) {
            from()
            description("reqwest error")
            display("HTTP error: {}", err)
            cause(err)
        }
        Other(err: String) {
            from()
        }
    }
}


fn run() -> Result<(), Error> {
    let repo = git2::Repository::open_from_env()?;

    println!("Finding commits...");

    let mut walker = repo.revwalk()?;
    walker.push_ref("refs/remotes/origin/develop")?;
    walker.hide_ref("refs/remotes/origin/master")?;

    let re = regex::Regex::new(r"Merge pull request #(\d+) from").expect("invalid regex");

    let merged_pull_requests: Vec<_> = walker
        .into_iter()
        .filter_map(
            |oid| {
                let oid = oid.expect("failed to walk revs");
                let mut commit = repo.find_commit(oid).expect("failed to find commit");
                commit
                    .summary()
                    .and_then(|summary| re.captures(summary))
                    .map(|groups| groups[1].to_string())
            },
        )
        .collect();

    println!("Downloading metadata from github...");

    let pb = Arc::new(Mutex::new(ProgressBar::new(merged_pull_requests.len() as u64)),);

    let mut client = reqwest::Client::new().unwrap();
    client.gzip(true);

    let bearer = Bearer { token: "ef66865d70e6cc2500b958f521092f0e3db02753".to_owned() };
    let auth_header = Authorization(bearer);

    let pool = scoped_pool::Pool::new(4);

    let issues = Vec::with_capacity(merged_pull_requests.len());
    let arced_issues = Arc::new(Mutex::new(issues));

    pool.scoped(
        |scope| for pr in merged_pull_requests {
            let issues_cloned = arced_issues.clone();
            let pb_cloned = pb.clone();
            let client_cloned = client.clone();
            let auth_cloned = auth_header.clone();
            scope.execute(
                move || {
                    let url = format!(
                        "https://api.github.com/repos/matrix-org/synapse/issues/{}",
                        pr
                    );
                    let mut resp = client_cloned
                        .get(&url)
                        .header(auth_cloned)
                        .send()
                        .expect("failed to get issue from github");

                    if !resp.status().is_success() {
                        panic!(format!("HTTP Error: {}", resp.status()));
                    }

                    let resp: GithubIssuesResponse =
                        resp.json().expect("failed to parse issue response");
                    issues_cloned.lock().unwrap().push(resp);

                    pb_cloned.lock().unwrap().inc(1);
                },
            );
        },
    );

    pb.lock().unwrap().finish();

    let issues = Arc::try_unwrap(arced_issues)
        .unwrap()
        .into_inner()
        .unwrap();

    let mut resp = client
        .get("https://api.github.com/teams/957027/members")
        .header(auth_header.clone())
        .send()?;

    if !resp.status().is_success() {
        return Err(format!("HTTP Error: {}", resp.status()).into());
    }

    println!("Fetching org members...");

    let org_members_json: Vec<GithubUser> = resp.json()?;
    let org_members: BTreeSet<_> = org_members_json.into_iter().map(|u| u.login).collect();


    let mut features = Vec::new();
    let mut changes = Vec::new();
    let mut bugs = Vec::new();
    let mut docs = Vec::new();
    let mut unknown = Vec::new();


    for issue in issues {
        let entry = if org_members.contains(&issue.user.login) {
            format!("* {} (PR #{})", issue.title.trim(), issue.number)
        } else {
            format!(
                "* {} (PR #{}) Thanks to @{}!",
                issue.title.trim(),
                issue.number,
                issue.user.login
            )
        };

        let labels: BTreeSet<_> = issue.labels.into_iter().map(|l| l.name).collect();
        if labels.contains("feature") {
            features.push(entry);
        } else if labels.contains("maintenance") {
            changes.push(entry);
        } else if labels.contains("bug") {
            bugs.push(entry);
        } else if labels.contains("docs") {
            docs.push(entry);
        } else {
            unknown.push(entry);
        }
    }

    println!();

    let sections = &[
        ("Features", features),
        ("Changes", changes),
        ("Bug fixes", bugs),
        ("Docs", docs),
        ("Misc", unknown),
    ];

    for &(ref name, ref entries) in sections {
        if !entries.is_empty() {
            println!("{}:\n", name);

            for entry in entries {
                println!("{}", entry);
            }

            println!("\n");
        }
    }

    Ok(())
}


#[derive(Debug, Clone, Deserialize)]
struct GithubIssuesResponse {
    number: u64,
    title: String,
    user: GithubUser,
    labels: Vec<GithubLabel>,
}


#[derive(Debug, Clone, Deserialize)]
struct GithubLabel {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubUser {
    login: String,
}


fn main() {
    run().unwrap();
}
