import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import sendMailerRoute from './sendMailer/index.js';
import jsonServer from 'json-server';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();

app.use(cookieParser());
const corsOptions = {
  origin: ['http://localhost:3000', 'https://young-citadel-44598.herokuapp.com'],
  credentials: true,
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
      firstname: req.body.firstname,
      lastname: req.body.lastname,
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
      let token = jwt.sign(userInfoWithoutPassword, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Set secure flag for HTTPS in production only
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
        console.error('JWT error:', err);
        if (err.name === 'TokenExpiredError') {
          return res.status(403).send('Token has expired');
        } else if (err.name === 'JsonWebTokenError') {
          return res.status(403).send('Invalid token');
        } else {
          return res.sendStatus(403);
        }
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
  const { name, background } = req.body;

  try {
    console.log("name -> ", name)
    const sortId = router.db.get('boards').value().length + 1;
    const newBoard = router.db.get('boards').insert({ name, background, userId: req.user.id, sortId }).write();
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

app.get('/boards/:boardId', authenticateJWT, (req, res) => {
  // Access the userId from the JWT
  const userId = req.user.id;

  // Access the boardId from the request parameters
  const boardId = Number(req.params.boardId);

  // Fetch the board from the database
  const board = router.db.get('boards')
    .find({ id: boardId, userId })
    .value();

  if (!board) {
    return res.status(404).json({ error: 'Board not found' });
  }

  res.status(200).json(board);
});

// Get sorted categories
app.get('/categories/:boardId', authenticateJWT, (req, res) => {
  const boardId = req.params.boardId;
  const categories = router.db.get('categories').filter({ boardId }).sortBy('sortId').value();
  res.status(200).json({categories, boardId});
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


// Update a board
app.put('/boards/:id', authenticateJWT, (req, res) => {
  const { name, background } = req.body;
  const id = Number(req.params.id);

  try {
    let board = router.db.get('boards').find({ id }).assign({ name, background }).write();
    res.status(200).json(board);
  } catch (error) {
    res.status(500).send('Error updating the board');
  }
});

// Delete a board
app.delete('/boards/:id', authenticateJWT, (req, res) => {
  const id = Number(req.params.id);
  const userId = req.user.id;
  try {
    const board = router.db.get('boards')
      .find({ id, userId })
      .value();
    if(board) {
      router.db.get('boards').remove({ id }).write();
      res.status(200).send('Board deleted successfully');
    } else {
      res.status(401).send('there is not such board');
    }
  } catch (error) {
    res.status(500).send('Error deleting the board');
  }
});

// Update a category
app.put('/categories/:id', authenticateJWT, (req, res) => {
  const { name } = req.body;
  const id = Number(req.params.id);

  try {
    let category = router.db.get('categories').find({ id }).assign({ name }).write();
    res.status(200).json(category);
  } catch (error) {
    res.status(500).send('Error updating the category');
  }
});

// Delete a category
app.delete('/categories/:id', authenticateJWT, (req, res) => {
  const id = Number(req.params.id);

  try {
    router.db.get('categories').remove({ id }).write();
    res.status(200).send('Category deleted successfully');
  } catch (error) {
    res.status(500).send('Error deleting the category');
  }
});

// Update a task
app.put('/tasks/:id', authenticateJWT, (req, res) => {
  const { name, description } = req.body;
  const id = Number(req.params.id);

  try {
    let task = router.db.get('tasks').find({ id }).assign({ name, description }).write();
    res.status(200).json(task);
  } catch (error) {
    res.status(500).send('Error updating the task');
  }
});

// Delete a task
app.delete('/tasks/:id', authenticateJWT, (req, res) => {
  const id = Number(req.params.id);

  try {
    router.db.get('tasks').remove({ id }).write();
    res.status(200).send('Task deleted successfully');
  } catch (error) {
    res.status(500).send('Error deleting the task');
  }
});

// Create a new comment for a task
app.post('/tasks/:taskId/comments', authenticateJWT, (req, res) => {
  const { comment } = req.body;
  const taskId = Number(req.params.id);
  const user = req.user;

  try {
    const id = Date.now();
    const userInfo = {
      id: user.id,
      firstname: user.firstname,
      lastname: user.lastname,
      email: user.email,
      gender: user.gender,
    }
    const newComment = { id, taskId, comment, userInfo, date: new Date() };
    const createdComment = router.db.get('comments').push(newComment).write();

    res.status(201).json({
      ...createdComment,
      userInfo
    });
  } catch (error) {
    res.status(500).send('Error creating the comment');
  }
});

// Edit a comment
app.put('/comments/:commentId', authenticateJWT, (req, res) => {
  const { comment } = req.body;
  const commentId = Number(req.params.id);
  const user = req.user;

  try {
    let commentToUpdate = router.db.get('comments').find({ id: commentId }).value();

    // Check if comment exists
    if (!commentToUpdate) {
      return res.status(404).send('Comment not found');
    }

    // Check if user is the owner of the comment
    if (commentToUpdate.userInfo.id !== user.id) {
      return res.status(403).send('Cannot edit a comment from another user');
    }

    const updatedComment = { ...commentToUpdate, comment, date: new Date() };
    router.db.get('comments').find({ id: commentId }).assign(updatedComment).write();

    res.status(200).json(updatedComment);
  } catch (error) {
    res.status(500).send('Error updating the comment');
  }
});

// Delete a comment
app.delete('/comments/:commentId', authenticateJWT, (req, res) => {
  const commentId = req.params.commentId;
  const user = req.user;

  try {
    let commentToDelete = router.db.get('comments').find({ id: commentId }).value();

    // Check if comment exists
    if (!commentToDelete) {
      return res.status(404).send('Comment not found');
    }

    // Check if user is the owner of the comment
    if (commentToDelete.userInfo.id !== user.id) {
      return res.status(403).send('Cannot delete a comment from another user');
    }

    router.db.get('comments').remove({ id: commentId }).write();
    res.status(200).send('Comment deleted successfully');
  } catch (error) {
    res.status(500).send('Error deleting the comment');
  }
});


app.use('/sendMailer', sendMailerRoute);




const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));



