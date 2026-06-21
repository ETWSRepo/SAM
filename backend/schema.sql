-- Silent Auction Manager - MySQL Schema
-- Run this on your Hostinger database: u177039107_sam

CREATE TABLE IF NOT EXISTS auctions (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  status VARCHAR(50) DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
  id CHAR(36) PRIMARY KEY,
  auction_id CHAR(36) NOT NULL,
  item_number VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  item_value VARCHAR(50),
  category_code VARCHAR(10),
  category_name VARCHAR(100),
  donor_name VARCHAR(255),
  donor_email VARCHAR(255),
  donor_phone VARCHAR(20),
  reserve_amount VARCHAR(50),
  email_message_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (auction_id) REFERENCES auctions(id) ON DELETE CASCADE,
  INDEX idx_auction (auction_id)
);

CREATE TABLE IF NOT EXISTS bidders (
  id CHAR(36) PRIMARY KEY,
  auction_id CHAR(36) NOT NULL,
  bidder_number INT NOT NULL,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  email VARCHAR(255),
  phone VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (auction_id) REFERENCES auctions(id) ON DELETE CASCADE,
  UNIQUE KEY unique_bidder (auction_id, bidder_number),
  INDEX idx_auction (auction_id)
);

CREATE TABLE IF NOT EXISTS winners (
  id CHAR(36) PRIMARY KEY,
  auction_id CHAR(36) NOT NULL,
  item_id CHAR(36) NOT NULL,
  bidder_id CHAR(36) NOT NULL,
  winning_bid VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (auction_id) REFERENCES auctions(id) ON DELETE CASCADE,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
  FOREIGN KEY (bidder_id) REFERENCES bidders(id) ON DELETE CASCADE,
  UNIQUE KEY unique_winner (auction_id, item_id),
  INDEX idx_auction (auction_id)
);

CREATE TABLE IF NOT EXISTS payments (
  id CHAR(36) PRIMARY KEY,
  auction_id CHAR(36) NOT NULL,
  bidder_id CHAR(36) NOT NULL,
  method VARCHAR(50),
  amount VARCHAR(50),
  paid BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (auction_id) REFERENCES auctions(id) ON DELETE CASCADE,
  FOREIGN KEY (bidder_id) REFERENCES bidders(id) ON DELETE CASCADE,
  INDEX idx_auction (auction_id),
  INDEX idx_bidder (bidder_id)
);

CREATE TABLE IF NOT EXISTS settings (
  id CHAR(36) PRIMARY KEY,
  auction_id CHAR(36) NOT NULL,
  setting_key VARCHAR(100),
  setting_value LONGTEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (auction_id) REFERENCES auctions(id) ON DELETE CASCADE,
  UNIQUE KEY unique_setting (auction_id, setting_key),
  INDEX idx_auction (auction_id)
);