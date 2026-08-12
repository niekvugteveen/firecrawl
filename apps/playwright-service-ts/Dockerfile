FROM node:18-slim

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install

COPY . .

ENV PLAYWRIGHT_BROWSERS_PATH=/usr/local/share/playwright

# Install Playwright dependencies.
# `chrome` installs real Google Chrome, which api.ts launches via
# channel:'chrome' -- see the comment there for why the bundled
# chromium_headless_shell is not usable against bot management. Chromium stays
# installed as a fallback for any launch that does not specify a channel.
RUN npx playwright install chromium --with-deps \
 && npx playwright install chrome --with-deps

RUN npm run build

ARG PORT
ENV PORT=${PORT}

EXPOSE ${PORT}

CMD [ "npm", "start" ]
