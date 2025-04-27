# Use official nginx (web server) image
FROM nginx:alpine

# Remove default nginx website
RUN rm -rf /usr/share/nginx/html/*

# Copy our own website files into nginx folder
COPY . /usr/share/nginx/html

# Fix permissions: make files readable
RUN chmod -R 755 /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Start nginx automatically
CMD ["nginx", "-g", "daemon off;"]
