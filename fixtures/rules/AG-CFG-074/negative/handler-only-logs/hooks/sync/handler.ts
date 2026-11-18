let count = 0;
export default async function handler(event) {
  count += 1;
  console.log(`messages: ${count}`);
}
