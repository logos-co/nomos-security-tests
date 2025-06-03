use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use kzgrs_backend::dispersal::BlobInfo;
use nomos_core::{da::blob::info::DispersedBlobInfo, tx::Transaction};
use nomos_mempool::{
    network::adapters::libp2p::Settings as AdapterSettings, tx::settings::TxMempoolSettings,
};
use nomos_node::{
    config::BlendArgs, Config, CryptarchiaArgs, HttpArgs, LogArgs, NetworkArgs, Nomos,
    NomosServiceSettings, Tx,
};
use overwatch::overwatch::OverwatchRunner;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path for a yaml-encoded network config file
    config: std::path::PathBuf,
    /// Overrides log config.
    #[clap(flatten)]
    log: LogArgs,
    /// Overrides network config.
    #[clap(flatten)]
    network: NetworkArgs,
    /// Overrides blend config.
    #[clap(flatten)]
    blend: BlendArgs,
    /// Overrides http config.
    #[clap(flatten)]
    http: HttpArgs,
    #[clap(flatten)]
    cryptarchia: CryptarchiaArgs,
}

fn main() -> Result<()> {
    let Args {
        config,
        log: log_args,
        http: http_args,
        network: network_args,
        blend: blend_args,
        cryptarchia: cryptarchia_args,
    } = Args::parse();
    let config = serde_yaml::from_reader::<_, Config>(std::fs::File::open(config)?)?
        .update_from_args(
            log_args,
            network_args,
            blend_args,
            http_args,
            cryptarchia_args,
        )?;

    let app = OverwatchRunner::<Nomos>::run(
        NomosServiceSettings {
            network: config.network,
            blend: config.blend,
            #[cfg(feature = "tracing")]
            tracing: config.tracing,
            http: config.http,
            cl_mempool: TxMempoolSettings {
                pool: (),
                network_adapter: AdapterSettings {
                    topic: String::from(nomos_node::CL_TOPIC),
                    id: <Tx as Transaction>::hash,
                },
                recovery_path: config.mempool.cl_pool_recovery_path,
            },
            da_mempool: nomos_mempool::DaMempoolSettings {
                pool: (),
                network_adapter: AdapterSettings {
                    topic: String::from(nomos_node::DA_TOPIC),
                    id: <BlobInfo as DispersedBlobInfo>::blob_id,
                },
                recovery_path: config.mempool.da_pool_recovery_path,
            },
            da_network: config.da_network,
            da_indexer: config.da_indexer,
            da_sampling: config.da_sampling,
            da_verifier: config.da_verifier,
            cryptarchia: config.cryptarchia,
            time: config.time,
            storage: config.storage,
            system_sig: (),
        },
        None,
    )
    .map_err(|e| eyre!("Error encountered: {}", e))?;
    app.runtime().block_on(app.handle().start_all_services());
    app.wait_finished();
    Ok(())
}
