// Keep legacy installer links usable without contacting the retired server.
export default {
  fetch(request) {
    const url = new URL(request.url);
    if (url.hostname !== 'install-selfhost.lets-script.com') {
      return new Response('Not Found', { status: 404 });
    }
    url.protocol = 'https:';
    url.hostname = 'install-selfhost.never-lost.app';
    url.port = '';
    return new Response(null, {
      status: 308,
      headers: {
        Location: url.toString(),
        'Cache-Control': 'public, max-age=300'
      }
    });
  }
};
