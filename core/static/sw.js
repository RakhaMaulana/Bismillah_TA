// Enhanced Service Worker for Crypvote PWA with Background Sync
const CACHE_NAME = 'crypvote-v2';
const STATIC_CACHE = 'crypvote-static-v2';
const DYNAMIC_CACHE = 'crypvote-dynamic-v2';

const urlsToCache = [
    '/',
    '/static/style.css',
    '/static/icon.ico',
    '/static/manifest.json',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    'https://code.jquery.com/jquery-3.7.1.min.js',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'
];

// Install event with enhanced caching
self.addEventListener('install', (event) => {
    console.log('Service Worker installing...');
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then((cache) => {
                console.log('Static cache opened');
                return cache.addAll(urlsToCache);
            })
            .then(() => {
                console.log('Service Worker installed successfully');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('Cache install failed:', error);
            })
    );
});

// Enhanced fetch event with network-first strategy for dynamic content
self.addEventListener('fetch', (event) => {
    if (event.request.url.includes('/api/') || event.request.url.includes('/vote')) {
        // Network-first strategy for API calls and voting
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    const responseClone = response.clone();
                    caches.open(DYNAMIC_CACHE)
                        .then((cache) => {
                            cache.put(event.request, responseClone);
                        });
                    return response;
                })
                .catch(() => {
                    return caches.match(event.request);
                })
        );
    } else {
        // Cache-first strategy for static assets
        event.respondWith(
            caches.match(event.request)
                .then((response) => {
                    if (response) {
                        return response;
                    }
                    return fetch(event.request)
                        .then((response) => {
                            const responseClone = response.clone();
                            caches.open(DYNAMIC_CACHE)
                                .then((cache) => {
                                    cache.put(event.request, responseClone);
                                });
                            return response;
                        });
                })
        );
    }
});

// Enhanced activate event with better cache management
self.addEventListener('activate', (event) => {
    console.log('Service Worker activating...');
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => {
            console.log('Service Worker activated');
            return self.clients.claim();
        })
    );
});

// Background sync for offline vote submission
self.addEventListener('sync', (event) => {
    console.log('Background sync triggered:', event.tag);
    if (event.tag === 'vote-sync') {
        event.waitUntil(syncVotes());
    }
});

// Push notification support
self.addEventListener('push', (event) => {
    console.log('Push received:', event);
    const options = {
        body: event.data ? event.data.text() : 'New notification from Crypvote',
        icon: '/static/icon.ico',
        badge: '/static/icon.ico',
        vibrate: [100, 50, 100],
        data: {
            dateOfArrival: Date.now(),
            primaryKey: 1
        },
        actions: [
            {
                action: 'explore',
                title: 'View Details',
                icon: '/static/icon.ico'
            },
            {
                action: 'close',
                title: 'Close',
                icon: '/static/icon.ico'
            }
        ]
    };

    event.waitUntil(
        self.registration.showNotification('Crypvote', options)
    );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
    console.log('Notification clicked:', event);
    event.notification.close();

    if (event.action === 'explore') {
        event.waitUntil(
            clients.openWindow('/')
        );
    }
});

// Background sync function for offline votes
async function syncVotes() {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const requests = await cache.keys();

        for (const request of requests) {
            if (request.url.includes('/vote') && request.method === 'POST') {
                try {
                    await fetch(request);
                    await cache.delete(request);
                    console.log('Synced offline vote:', request.url);
                } catch (error) {
                    console.log('Failed to sync vote:', error);
                }
            }
        }
    } catch (error) {
        console.error('Background sync failed:', error);
    }
}
