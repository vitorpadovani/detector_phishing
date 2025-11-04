import dotenv from 'dotenv';
dotenv.config();

export const CONFIG = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  FEED_TTL_HOURS: parseInt(process.env.FEED_TTL_HOURS || '2', 10),
  GSB_KEY: process.env.GOOGLE_SAFEBROWSING_API_KEY || ''
};
