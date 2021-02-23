use ockam::{Context, Result, Worker};

struct Echoer;

impl Worker for Echoer {
    type Message = String;
    type Context = Context;

    fn handle_message(&mut self, ctx: &mut Context, msg: String) -> Result<()> {
        ctx.send_message("app", format!("{}", msg))
    }
}

#[ockam::node]
async fn main(mut ctx: Context) -> Result<()> {
    ctx.start_worker("echoer", Echoer)?;

    ctx.send_message("echoer", "Hello Ockam!".to_string())?;

    let reply = ctx.receive::<String>()?;
    println!("Reply: {}", reply);

    ctx.stop()
}