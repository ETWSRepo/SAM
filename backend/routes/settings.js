const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/connection');

const router = express.Router();

// GET all settings for auction
router.get('/:auctionId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM settings WHERE auction_id = ?',
      [req.params.auctionId]
    );
    const settings = {};
    rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    res.json(settings);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single setting
router.get('/:auctionId/:key', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM settings WHERE auction_id = ? AND setting_key = ?',
      [req.params.auctionId, req.params.key]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Setting not found' });
    }
    res.json({ [rows[0].setting_key]: rows[0].setting_value });
  } catch (error) {
    console.error('Error fetching setting:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST/PUT upsert settings (bulk)
router.post('/:auctionId', async (req, res) => {
  try {
    const settings = req.body;
    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Settings object required' });
    }

    for (const [key, value] of Object.entries(settings)) {
      const [existing] = await pool.query(
        'SELECT id FROM settings WHERE auction_id = ? AND setting_key = ?',
        [req.params.auctionId, key]
      );

      if (existing.length > 0) {
        await pool.query(
          'UPDATE settings SET setting_value = ? WHERE auction_id = ? AND setting_key = ?',
          [JSON.stringify(value), req.params.auctionId, key]
        );
      } else {
        const id = uuidv4();
        await pool.query(
          'INSERT INTO settings (id, auction_id, setting_key, setting_value) VALUES (?, ?, ?, ?)',
          [id, req.params.auctionId, key, JSON.stringify(value)]
        );
      }
    }

    // Return updated settings
    const [rows] = await pool.query(
      'SELECT * FROM settings WHERE auction_id = ?',
      [req.params.auctionId]
    );
    const result = {};
    rows.forEach(row => {
      try {
        result[row.setting_key] = JSON.parse(row.setting_value);
      } catch {
        result[row.setting_key] = row.setting_value;
      }
    });
    res.json(result);
  } catch (error) {
    console.error('Error saving settings:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE setting
router.delete('/:auctionId/:key', async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM settings WHERE auction_id = ? AND setting_key = ?',
      [req.params.auctionId, req.params.key]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting setting:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
