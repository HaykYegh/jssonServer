import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jsonServer from 'json-server';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();

app.use(cookieParser());
const corsOptions = {
  origin: 'http://localhost:3000', // replace with your actual domain
  credentials: true, // allow the cookie to be sent with the request
};
app.use(cors(corsOptions));

app.use(bodyParser.json());

// Start JSON Server
let router = jsonServer.router('db.json'); // use the db.json file for the JSON Server
let middlewares = jsonServer.defaults();

app.use('/api', middlewares, router); // all JSON Server routes are now prefixed with '/api'

app.post('/register', async (req, res) => {
  if (!req.body.password || typeof req.body.password !== 'string') {
    return res.status(400).send('Invalid password');
  }

  try {
    // Check if user already exists
    let existingUser = router.db.get('users')
      .find({ email: req.body.email })
      .value();

    if (existingUser) {
      return res.status(400).send('User with given email already exists');
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const id = Date.now();

    let newUser = {
      id,
      username: req.body.username,
      password: hashedPassword,
      age: req.body.age,
      email: req.body.email,
      gender: req.body.gender,
    };

    let user = router.db.get('users')
      .push(newUser)
      .write();

    res.status(200).send('User added successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering user');
  }
});

app.post('/login', async (req, res) => {
  try {
    let user = router.db.get('users')
      .find({ email: req.body.email }) // find by email instead of username
      .value();

    if (!user) {
      return res.status(400).send('Cannot find user');
    }

    if (await bcrypt.compare(req.body.password, user.password)) {
      // User authenticated successfully, generate a JWT
      const { password, ...userInfoWithoutPassword } = user;
      let token = jwt.sign(userInfoWithoutPassword, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, {
        httpOnly: true, // Make the cookie HTTP-only
        secure: true, // Set secure flag for HTTPS
        sameSite: 'none', // Prevent CSRF
      });

      res.status(200).json({ message: 'User authenticated successfully', token });
    } else {
      res.status(400).send('Incorrect password');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: 'User logged out successfully' });
});

// Middleware to authenticate JWT
function authenticateJWT(req, res, next) {
  const token = req.cookies.token;

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}

app.get('/user', authenticateJWT, async (req, res) => {
  try {
    let user = router.db.get('users')
      .find({ email: req.user.email })
      .value();

    if (!user) {
      return res.status(400).send('Cannot find user');
    }

    // Exclude password field from the response
    let userInfo = { ...user };
    delete userInfo.password;

    res.status(200).json(userInfo);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving user');
  }
});


// Create a new board
app.post('/boards', authenticateJWT, (req, res) => {
  const { name } = req.body;

  try {
    const sortId = router.db.get('boards').value().length + 1;
    const newBoard = router.db.get('boards').insert({ name, userId: req.user.id, sortId }).write();
    res.status(201).json(newBoard);
  } catch (error) {
    res.status(500).send('Error creating the board');
  }
});

// Create a new category
app.post('/categories', authenticateJWT, (req, res) => {
  const { name, boardId } = req.body;

  try {
    const sortId = router.db.get('categories').value().length + 1;
    const newCategory = router.db.get('categories').insert({ name, boardId, sortId }).write();
    res.status(201).json(newCategory);
  } catch (error) {
    res.status(500).send('Error creating the category');
  }
});

// Create a new task
app.post('/tasks', authenticateJWT, (req, res) => {
  const { name, description, categoryId } = req.body;

  try {
    const sortId = router.db.get('tasks').value().length + 1;
    const newTask = router.db.get('tasks').insert({ name, description, categoryId, sortId }).write();
    res.status(201).json(newTask);
  } catch (error) {
    res.status(500).send('Error creating the task');
  }
});


// Get sorted boards
app.get('/boards', authenticateJWT, (req, res) => {
  // Access the userId from the JWT
  const userId = req.user.id;

  // Filter boards by userId
  const userBoards = router.db.get('boards')
    .filter({ userId })
    .sortBy('sortId')
    .value();

  res.status(200).json(userBoards);
});

// Get sorted categories
app.get('/categories/:boardId', authenticateJWT, (req, res) => {
  const boardId = req.params.boardId;
  const categories = router.db.get('categories').filter({ boardId }).sortBy('sortId').value();
  res.status(200).json(categories);
});

// Get sorted tasks
app.get('/tasks/:categoryId', authenticateJWT, (req, res) => {
  const categoryId = req.params.categoryId
  const tasks = router.db.get('tasks').filter({ categoryId }).sortBy('sortId').value();
  res.status(200).json(tasks);
});

app.get('/tasks/:taskId', authenticateJWT, (req, res) => {
  const { taskId } = req.params;

  // It's assumed that the task database has entries structured like { taskId, userId, ...taskData }
  const task = router.db.get('tasks').find({ taskId }).value();

  if (task) {
    res.status(200).json(task);
  } else {
    res.status(404).json({ message: 'Task not found' });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
