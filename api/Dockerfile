FROM node:10-alpine

# Create the working dir and copy app files
RUN mkdir -p /var/www && mkdir /cache && mkdir -p /advaita-results
WORKDIR /var/www

# Do not use cache when we change node dependencies in package.json
ADD package.json yarn.lock /cache/

# Update OS Install packages + Prepare cache file
RUN apk --no-cache add ca-certificates wget git python alpine-sdk libusb-dev yarn && update-ca-certificates \
  && cd /cache \
  && yarn config set cache-folder /usr/local/share/.cache/yarn \
  && yarn \
  && yarn global add forever \
  && cd /var/www && ln -s /cache/node_modules node_modules \
  && tar czf /.yarn-cache.tgz /usr/local/share/.cache/yarn

COPY . /var/www/

EXPOSE 5500
CMD ["forever", "./src/server.js"]
