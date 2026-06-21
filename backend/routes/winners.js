const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/connection');

const router = express.Router();

// GET winners for auction
router.get('/:auctionId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT w.*, i.item_number, b.bidder_number, b.first_name, b.last_name
       FROM winners w
       LEFT JOIN items i ON w.item_id = i.id
       LEFT JOIN bidders b ON w.bidder_id = b.id
       WHERE w.auction_id = ?
       ORDER BY i.item_number ASC`,
      [req.params.auctionId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching winners:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single winner
router.get('/:auctionId/:winnerId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM winners WHERE id = ? AND auction_id = ?',
      [req.params.winnerId, req.params.auctionId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Winner not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching winner:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create winner
router.post('/:auctionId', async (req, res) => {
  try {
    const { item_id, bidder_id, winning_bid } = req.body;

    if (!item_id || !bidder_id) {
      return res.status(400).json({ error: 'item_id and bidder_id required' });
    }

    const id = uuidv4();
    await pool.query(
      'INSERT INTO winners (id, auction_id, item_id, bidder_id, winning_bid) VALUES (?, ?, ?, ?, ?)',
      [id, req.params.auctionId, item_id, bidder_id, winning_bid]
    );

    const [rows] = await pool.query('SELECT * FROM winners WHERE id = ?', [id]);
    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Error creating winner:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update winner
router.put('/:auctionId/:winnerId', async (req, res) => {
  try {
    const { winning_bid } = req.body;
    const updates = [];
    const values = [];

    if (winning_bid !== undefined) {
      updates.push('winning_bid = ?');
      values.push(winning_bid);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.winnerId);
    values.push(req.params.auctionId);
    await pool.query(`UPDATE winners SET ${updates.join(', ')} WHERE id = ? AND auction_id = ?`, values);

    const [rows] = await pool.query('SELECT * FROM winners WHERE id = ?', [req.params.winnerId]);
    res.json(rows[0]);
  } catch (error) {
    console.error('Error updating winner:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE winner
router.delete('/:auctionId/:winnerId', async (req, res) => {
  try {
    await pool.query('DELETE FROM winners WHERE id = ? AND auction_id = ?',
                     [req.params.winnerId, req.params.auctionId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting winner:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
