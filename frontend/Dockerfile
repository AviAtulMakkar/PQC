FROM nginx:1.25-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy EVERYTHING in this folder (index.html, style.css, app.js) to the web server
COPY . /usr/share/nginx/html/

# Copy your specific nginx site config to the config folder
COPY default.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]