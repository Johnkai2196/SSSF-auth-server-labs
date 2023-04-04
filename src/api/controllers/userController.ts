// Description: This file contains the functions for the user routes
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import userModel from '../models/userModel';
import {OutputUser, User} from '../../interfaces/User';
import bcrypt from 'bcryptjs';
import DBMessageResponse from '../../interfaces/DBMessageResponse';
import jwt from 'jsonwebtoken';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';

const salt = bcrypt.genSaltSync(12);
// TODO: add function check, to check if the server is alive
const check = (req: Request, res: Response) => {
  res.json({message: 'Server is alive'});
};

// TODO: add function to get all users
const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const users = await userModel.find().select('-password -role');
    res.json(users);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: add function to get a user by id
const userGet = async (
  req: Request<{id: String}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await userModel
      .findById(req.params.id)
      .select('-password -role');
    if (!user) {
      next(new CustomError('User not found', 404));
    }
    res.json(user);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: add function to create a user
const userPost = async (
  req: Request<{}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = req.body;
    user.password = await bcrypt.hash(user.password, salt);
    const newUser = await userModel.create(user);
    const response: DBMessageResponse = {
      message: 'User created',
      user: {
        user_name: newUser.user_name,
        email: newUser.email,
        id: newUser._id,
      },
    };
    res.json(response);
    res.json(newUser);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: add function to update a user
const userPut = async (
  req: Request<{}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    const headers = req.headers;
    const bearer = headers.authorization;
    if (!bearer) {
      next(new CustomError('No token provided', 401));
      return;
    }
    const token = bearer.split(' ')[1];
    const userFromToken = jwt.verify(
      token,
      process.env.JWT_SECRET as string
    ) as OutputUser;

    const user = req.body;
    if (user.password) {
      user.password = await bcrypt.hash(user.password, salt);
    }
    console.log(userFromToken.id, req.body);

    const result = await userModel
      .findByIdAndUpdate(userFromToken.id, user, {new: true})
      .select('-password -role');
    if (!result) {
      next(new CustomError('User not found', 404));
      return;
    }
    const response: DBMessageResponse = {
      message: 'User updated',
      user: {
        user_name: result.user_name,
        email: result.email,
        id: result._id,
      },
    };

    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: add function to delete a user
const userDelete = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const headers = req.headers;
    const bearer = headers.authorization;
    if (!bearer) {
      next(new CustomError('No token provided', 401));
      return;
    }
    const token = bearer.split(' ')[1];
    const userFromToken = jwt.verify(
      token,
      process.env.JWT_SECRET as string
    ) as OutputUser;

    const result = await userModel.findByIdAndDelete(userFromToken.id);
    if (!result) {
      next(new CustomError('User not found', 404));
      return;
    }
    const response: DBMessageResponse = {
      message: 'User deleted',
      user: {
        user_name: result.user_name,
        email: result.email,
        id: result._id,
      },
    };
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: add function to check if a token is valid
const checkToken = async (req: Request, res: Response, next: NextFunction) => {
  const headers = req.headers;
  const bearer = headers.authorization;
  if (!bearer) {
    next(new CustomError('No token provided', 401));
    return;
  }
  const token = bearer.split(' ')[1];
  const userFromToken = jwt.verify(
    token,
    process.env.JWT_SECRET as string
  ) as OutputUser;
  const user = await userModel
    .findById(userFromToken.id)
    .select('-password -role');
  if (!user) {
    next(new CustomError('Token not valid', 404));
    return;
  }
  const newToken = jwt.sign(
    {
      id: user._id,
    },
    process.env.JWT_SECRET as string
  );
  const message: LoginMessageResponse = {
    message: 'Token is valid',
    token: newToken,
  };
  res.json(message);
};

export {check, userListGet, userGet, userPost, userPut, userDelete, checkToken};
