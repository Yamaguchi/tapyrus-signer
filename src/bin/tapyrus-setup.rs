extern crate tapyrus_signer;

use clap::App;
use tapyrus_signer::cli::setup::aggregate::CreateAggregateCommand;
use tapyrus_signer::cli::setup::create_key::CreateKeyCommand;
use tapyrus_signer::cli::setup::create_node_vss::CreateNodeVssCommand;
use tapyrus_signer::cli::setup::create_block_vss::CreateBlockVssCommand;
use tapyrus_signer::cli::setup::sign::SignCommand;
use tapyrus_signer::cli::setup::computesig::ComputeSigCommand;
use tapyrus_signer::cli::setup::traits::Response;
use tapyrus_signer::errors::Error;

fn main() {
    let matches = App::new("Setup")
        .subcommand(CreateKeyCommand::args())
        .subcommand(CreateNodeVssCommand::args())
        .subcommand(CreateAggregateCommand::args())
        .subcommand(CreateBlockVssCommand::args())
        .subcommand(SignCommand::args())
        .subcommand(ComputeSigCommand::args())
        .get_matches();
    let result: Result<Box<dyn Response>, Error> = match matches.subcommand_name() {
        Some("createkey") => CreateKeyCommand::execute(
            matches
                .subcommand_matches("createkey")
                .expect("invalid args"),
        ),
        Some("createnodevss") => CreateNodeVssCommand::execute(
            matches
                .subcommand_matches("createnodevss")
                .expect("invalid args"),
        ),
        Some("aggregate") => CreateAggregateCommand::execute(
            matches
                .subcommand_matches("aggregate")
                .expect("invalid args"),
        ),
        Some("createblockvss") => CreateBlockVssCommand::execute(
            matches
                .subcommand_matches("createblockvss")
                .expect("invalid args"),
        ),
        Some("sign") => SignCommand::execute(
            matches
                .subcommand_matches("sign")
                .expect("invalid args"),
        ),
        Some("computesig") => ComputeSigCommand::execute(
            matches
                .subcommand_matches("computesig")
                .expect("invalid args"),
        ),
        None => return println!("No subcommand was used"),
        _ => unreachable!(),
    };
    match result {
        Ok(response) => println!("{}", response),
        Err(e) => println!("{}", e),
    }
}
