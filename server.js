require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;

// Initialize Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// File upload configuration
const upload = multer({
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow images and documents
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedTypes.test(file.originalname.toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Role-based access control
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, role, unitNumber } = req.body;

    // Validate required fields
    if (!email || !password || !firstName || !lastName || !role) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('email')
      .eq('email', email)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const { data: user, error } = await supabase
      .from('users')
      .insert([
        {
          email,
          password: hashedPassword,
          first_name: firstName,
          last_name: lastName,
          role,
          unit_number: unitNumber,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to create user' });
    }

    // Generate tokens
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    // Save refresh token
    await supabase
      .from('users')
      .update({ refresh_token: refreshToken })
      .eq('id', user.id);

    res.json({
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        unitNumber: user.unit_number
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Get user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate tokens
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    // Save refresh token
    await supabase
      .from('users')
      .update({ refresh_token: refreshToken })
      .eq('id', user.id);

    res.json({
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        unitNumber: user.unit_number
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Get user and verify refresh token
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .eq('refresh_token', refreshToken)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Generate new access token
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ============ USER ROUTES ============

// Get current user
app.get('/api/user/me', authenticateToken, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    firstName: req.user.first_name,
    lastName: req.user.last_name,
    role: req.user.role,
    unitNumber: req.user.unit_number
  });
});

// ============ DUES ROUTES ============

// Get user dues
app.get('/api/dues', authenticateToken, async (req, res) => {
  try {
    const { data: dues, error } = await supabase
      .from('dues')
      .select('*')
      .eq('user_id', req.user.id)
      .order('due_date', { ascending: false });

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch dues' });
    }

    res.json(dues || []);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get dues summary
app.get('/api/dues/summary', authenticateToken, async (req, res) => {
  try {
    const { data: dues, error } = await supabase
      .from('dues')
      .select('*')
      .eq('user_id', req.user.id);

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch dues' });
    }

    const totalOwed = dues.reduce((sum, due) => sum + (due.status === 'pending' ? due.amount : 0), 0);
    const nextDueDate = dues.find(due => due.status === 'pending')?.due_date;

    res.json({
      totalOwed,
      nextDueDate,
      monthlyDues: 150.00 // This could be dynamic based on unit type
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Pay dues
app.post('/api/dues/pay', authenticateToken, async (req, res) => {
  try {
    const { duesId, paymentMethod } = req.body;

    // In a real app, you'd process payment with Stripe here
    
    const { data: due, error } = await supabase
      .from('dues')
      .update({ 
        status: 'paid',
        paid_date: new Date().toISOString(),
        payment_method: paymentMethod
      })
      .eq('id', duesId)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to process payment' });
    }

    res.json({ success: true, due });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ VIOLATIONS ROUTES ============

// Get user violations
app.get('/api/violations', authenticateToken, async (req, res) => {
  try {
    const { data: violations, error } = await supabase
      .from('violations')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch violations' });
    }

    res.json(violations || []);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create violation (board only)
app.post('/api/violations', authenticateToken, requireRole(['board']), async (req, res) => {
  try {
    const { userId, violationType, description, fineAmount } = req.body;

    const { data: violation, error } = await supabase
      .from('violations')
      .insert([
        {
          user_id: userId,
          violation_type: violationType,
          description,
          fine_amount: fineAmount,
          status: 'active',
          created_by: req.user.id,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to create violation' });
    }

    res.json(violation);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ VOTING ROUTES ============

// Get voting topics
app.get('/api/voting', authenticateToken, async (req, res) => {
  try {
    const { data: topics, error } = await supabase
      .from('voting_topics')
      .select(`
        *,
        votes (
          user_id,
          vote_choice
        )
      `)
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch voting topics' });
    }

    res.json(topics || []);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create voting topic (board only)
app.post('/api/voting', authenticateToken, requireRole(['board']), async (req, res) => {
  try {
    const { title, description, options, endDate } = req.body;

    const { data: topic, error } = await supabase
      .from('voting_topics')
      .insert([
        {
          title,
          description,
          options,
          end_date: endDate,
          created_by: req.user.id,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to create voting topic' });
    }

    res.json(topic);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Submit vote
app.post('/api/voting/:topicId/vote', authenticateToken, async (req, res) => {
  try {
    const { topicId } = req.params;
    const { choice } = req.body;

    // Check if user already voted
    const { data: existingVote } = await supabase
      .from('votes')
      .select('id')
      .eq('topic_id', topicId)
      .eq('user_id', req.user.id)
      .single();

    if (existingVote) {
      return res.status(400).json({ error: 'You have already voted on this topic' });
    }

    const { data: vote, error } = await supabase
      .from('votes')
      .insert([
        {
          topic_id: topicId,
          user_id: req.user.id,
          vote_choice: choice,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to submit vote' });
    }

    res.json(vote);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ MAINTENANCE ROUTES ============

// Get maintenance requests
app.get('/api/maintenance', authenticateToken, async (req, res) => {
  try {
    let query = supabase
      .from('maintenance_requests')
      .select('*')
      .order('created_at', { ascending: false });

    // Residents can only see their own requests
    if (req.user.role === 'resident') {
      query = query.eq('user_id', req.user.id);
    }

    const { data: requests, error } = await query;

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch maintenance requests' });
    }

    res.json(requests || []);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create maintenance request
app.post('/api/maintenance', authenticateToken, upload.array('images', 5), async (req, res) => {
  try {
    const { title, description, priority, category } = req.body;
    
    // In a real app, you'd upload files to storage here
    const attachments = req.files ? req.files.map(file => ({
      filename: file.originalname,
      size: file.size,
      type: file.mimetype
    })) : [];

    const { data: request, error } = await supabase
      .from('maintenance_requests')
      .insert([
        {
          user_id: req.user.id,
          title,
          description,
          priority,
          category,
          status: 'new',
          attachments,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to create maintenance request' });
    }

    res.json(request);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ DOCUMENTS ROUTES ============

// Get documents
app.get('/api/documents', authenticateToken, async (req, res) => {
  try {
    const { data: documents, error } = await supabase
      .from('documents')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch documents' });
    }

    res.json(documents || []);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Upload document (board only)
app.post('/api/documents', authenticateToken, requireRole(['board']), upload.single('file'), async (req, res) => {
  try {
    const { title, category } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // In a real app, you'd upload to storage here
    const { data: document, error } = await supabase
      .from('documents')
      .insert([
        {
          title,
          category,
          filename: req.file.originalname,
          file_size: req.file.size,
          file_type: req.file.mimetype,
          uploaded_by: req.user.id,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to upload document' });
    }

    res.json(document);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ EVENTS ROUTES ============

// Get events
app.get('/api/events', authenticateToken, async (req, res) => {
  try {
    const { data: events, error } = await supabase
      .from('events')
      .select('*')
      .order('event_date', { ascending: true });

    if (error) {
      return res.status(400).json({ error: 'Failed to fetch events' });
    }

    res.json(events || []);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create event (board only)
app.post('/api/events', authenticateToken, requireRole(['board']), async (req, res) => {
  try {
    const { title, description, eventDate, location, maxAttendees } = req.body;

    const { data: event, error } = await supabase
      .from('events')
      .insert([
        {
          title,
          description,
          event_date: eventDate,
          location,
          max_attendees: maxAttendees,
          created_by: req.user.id,
          created_at: new Date().toISOString()
        }
      ])
      .select()
      .single();

    if (error) {
      return res.status(400).json({ error: 'Failed to create event' });
    }

    res.json(event);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`🚀 HOA Management API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});