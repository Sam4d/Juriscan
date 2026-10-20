// Synthetic excerpt, not runnable application code.
export async function POST(request: Request) {
  const event = await request.json();
  return stripe.fulfill(event);
}
