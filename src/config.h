/* See LICENSE file for copyright and license details. */
#define SERVER_PORT 8000
#define MAX_CLIENT 8
#define ALLOWED_FILES 17
#define SSL_CERT_FILE "./cert/cert.pem"
#define SSL_KEY_FILE "./cert/key.pem"

static const char* allowed_files[] = 
  {
    "error.html", 
    "", 
    "index.html", 
    "styles.css",
    "favicon.ico",
    "assets/android-chrome-192x192.png", 
    "assets/android-chrome-512x512.png",
    "assets/apple-touch-icon.png", 
    "assets/favicon-16x16.png",
    "assets/favicon-32x32.png", 
    "assets/favicon.ico",
    "assets/trollface-drift-phonk.gif",
    "assets/buttons/agplv3.png",
    "assets/buttons/archlinux.gif",
    "assets/buttons/linux_powered.gif", 
    "assets/buttons/vim.gif",
    "assets/buttons/wget.gif"
  };

