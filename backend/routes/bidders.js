const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/connection');

const router = express.Router();

// GET bidders for auction
router.get('/:auctionId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM bidders WHERE auction_id = ? ORDER BY bidder_number ASC',
      [req.params.auctionId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching bidders:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single bidder
router.get('/:auctionId/:bidderId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM bidders WHERE id = ? AND auction_id = ?',
      [req.params.bidderId, req.params.auctionId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Bidder not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching bidder:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create bidder (single or bulk)
router.post('/:auctionId', async (req, res) => {
  try {
    const isBulk = Array.isArray(req.body);
    const bidders = isBulk ? req.body : [req.body];

    const created = [];
    for (const bidder of bidders) {
      const { bidder_number, first_name, last_name, email, phone } = bidder;

      if (!bidder_number) continue;

      const id = uuidv4();
      await pool.query(
        'INSERT INTO bidders (id, auction_id, bidder_number, first_name, last_name, email, phone) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [id, req.params.auctionId, bidder_number, first_name, last_name, email, phone]
      );

      const [rows] = await pool.query('SELECT * FROM bidders WHERE id = ?', [id]);
      created.push(rows[0]);
    }

    res.status(201).json(isBulk ? created : created[0]);
  } catch (error) {
    console.error('Error creating bidder:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update bidder
router.put('/:auctionId/:bidderId', async (req, res) => {
  try {
    const fields = ['first_name', 'last_name', 'email', 'phone'];
    const updates = [];
    const values = [];

    fields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        values.push(req.body[field]);
      }
    });

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.params.bidderId);
    values.push(req.params.auctionId);
    await pool.query(`UPDATE bidders SET ${updates.join(', ')} WHERE id = ? AND auction_id = ?`, values);

    const [rows] = await pool.query('SELECT * FROM bidders WHERE id = ?', [req.params.bidderId]);
    res.json(rows[0]);
  } catch (error) {
    console.error('Error updating bidder:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE bidder
router.delete('/:auctionId/:bidderId', async (req, res) => {
  try {
    await pool.query('DELETE FROM bidders WHERE id = ? AND auction_id = ?',
                     [req.params.bidderId, req.params.auctionId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting bidder:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
