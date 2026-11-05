//! Console helper started inside Windows Terminal tabs (the GUI exe has no console in release builds).
//! `lzssh-ssh --launch <file>`: run the ssh invocation stored in <file> (file is deleted on read).
//! As SSH_ASKPASS (LZSSH_ASKPASS=1 + LZSSH_ASKPASS_TOKEN set): answer ssh's prompt.
fn main() {
    if std::env::var("LZSSH_ASKPASS").as_deref() == Ok("1") && std::env::var_os("LZSSH_ASKPASS_TOKEN").is_some() {
        std::process::exit(lzssh::askpass::client_main());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--launch" {
        std::process::exit(lzssh::connect::launch_main(std::path::Path::new(&args[2])));
    }
    eprintln!("lzssh-ssh is a helper for lzssh and is not meant to be run directly.");
    std::process::exit(2);
}
