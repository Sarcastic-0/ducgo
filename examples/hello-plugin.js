// ducgo example plugin - stdlib only.
// A plugin = one .js file exporting { name, version?, commands: [{ name, desc, usage?, run(ctx) }] }.
// Limits: plugins may ONLY add commands. They may NOT hook the trap engine or auth.
// ctx = { ui, args, config, store, callBuiltIn(name,args), dataDir }.
// Trust: only enable plugins you trust - they run as your user. Added DISABLED by default.
export default {
  name: 'hello-plugin',
  version: '1.0.0',
  commands: [
    {
      name: 'hello',
      desc: 'Say hello (example plugin command)',
      usage: 'ducgo hello [name]',
      async run(ctx) {
        const who = (ctx.args[0] || 'world').slice(0, 80);
        ctx.ui.ok(`Hello, ${who}! (from hello-plugin v1.0.0)`);
      },
    },
    {
      name: 'threat-tip',
      desc: 'Print a defensive tip (example plugin command)',
      usage: 'ducgo threat-tip',
      async run(ctx) {
        ctx.ui.info('Tip: review tripwires with "ducgo events" and "ducgo top-attackers".');
      },
    },
  ],
};
