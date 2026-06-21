const express = require('express');
const { v4: uuidv4 } = require('uuid');
const pool = require('../db/connection');

const router = express.Router();

// GET items for auction
router.get('/:auctionId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM items WHERE auction_id = ? ORDER BY created_at DESC',
      [req.params.auctionId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single item
router.get('/:auctionId/:itemId', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM items WHERE id = ? AND auction_id = ?',
      [req.params.itemId, req.params.auctionId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Item not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching item:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create item (single or bulk)
router.post('/:auctionId', async (req, res) => {
  try {
    // Check if bulk (array) or single (object)
    const isBulk = Array.isArray(req.body);
    const items = isBulk ? req.body : [req.body];

    const created = [];
    for (const item of items) {
      const {
        item_number, description, item_value, category_code, category_name,
        donor_name, donor_email, donor_phone, reserve_amount, email_message_id
      } = item;

      if (!item_number) continue;

      const id = uuidv4();
      await pool.query(
        `INSERT INTO items (
          id, auction_id, item_number, description, item_value, category_code,
          category_name, donor_name, donor_email, donor_phone, reserve_amount, email_message_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, req.params.auctionId, item_number, description, item_value, category_code,
         category_name, donor_name, donor_email, donor_phone, reserve_amount, email_message_id]
      );

      const [rows] = await pool.query('SELECT * FROM items WHERE id = ?', [id]);
      created.push(rows[0]);
    }

    res.status(201).json(isBulk ? created : created[0]);
  } catch (error) {
    console.error('Error creating item:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update item
router.put('/:auctionId/:itemId', async (req, res) => {
  try {
    const fields = ['description', 'item_value', 'category_code', 'category_name',
                    'donor_name', 'donor_email', 'donor_phone', 'reserve_amount'];
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

    values.push(req.params.itemId);
    values.push(req.params.auctionId);
    await pool.query(`UPDATE items SET ${updates.join(', ')} WHERE id = ? AND auction_id = ?`, values);

    const [rows] = await pool.query('SELECT * FROM items WHERE id = ?', [req.params.itemId]);
    res.json(rows[0]);
  } catch (error) {
    console.error('Error updating item:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE item
router.delete('/:auctionId/:itemId', async (req, res) => {
  try {
    await pool.query('DELETE FROM items WHERE id = ? AND auction_id = ?',
                     [req.params.itemId, req.params.auctionId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
