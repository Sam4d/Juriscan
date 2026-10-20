// A negative detector excerpt. Real deployments also require deduplication and business checks.
export async function POST(request: Request) {
  const event = stripe.webhooks.constructEvent(await request.text(), signature, endpointSecret);
  return handleVerifiedEvent(event);
}
