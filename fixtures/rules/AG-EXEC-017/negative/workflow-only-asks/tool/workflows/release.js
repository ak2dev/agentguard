export default async function run(ctx) {
  const ok = await ctx.ask('Ready to release?');
  return ok ? 'yes' : 'no';
}
