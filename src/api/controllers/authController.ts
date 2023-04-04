import {Request, Response, NextFunction} from 'express';
import userModel from '../models/userModel';
import CustomError from '../../classes/CustomError';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';
import {OutputUser} from '../../interfaces/User';

// TODO: Create login controller that creates a jwt token and returns it to the user
const login = async (
  req: Request<{}, {}, {username: string; password: string}>,
  res: Response,
  next: NextFunction
) => {
  const {username, password} = req.body;
  try {
    const user = await userModel.findOne({email: username});
    if (!user) {
      next(new CustomError('Incorrect username/password', 200));
      return;
    }
    if (!bcrypt.compareSync(password, user.password)) {
      next(new CustomError('Incorrect username/password', 200));
      return;
    }
    //set expiration depending on the app requirements. For example if social media app then no need, if banking app then 1 hour
    const token = jwt.sign({id: user._id}, process.env.JWT_SECRET as string);

    const outputUser: OutputUser = {
      user_name: user.user_name,
      email: user.email,
      id: user._id,
    };

    const message: LoginMessageResponse = {
      message: 'Login successful',
      token,
      user: outputUser,
    };

    res.json(message);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {login};
