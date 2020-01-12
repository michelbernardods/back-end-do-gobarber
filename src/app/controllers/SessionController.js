import * as Yup from 'yup';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import authentication from '../../config/authentication';

class SessionController {
    async store(req, res) {

//  Start validation to login of user !   
        const schema = Yup.object().shape({
            email: Yup.string().email().required(),
            password: Yup.string().required(),
        });

        if(!(await schema.isValid(req.body))) {
            return res.status(400).json({error: 'Validation fails'});
        }
//  End validation to login of user !     


        const { email, password } = req.body;

        const user = await User.findOne({where: {email} });

        if(!user) {
            return res.status(401).json({error: 'User not found'});
        }

        if(!await user.checkPassword(password)) {
            return res.status(401).json({error: 'Password does not match'});
        }

        const { id, name } = user;

        return res.json({
            user: {
                id,
                name,
                email,
            },
            token: jwt.sign({ id }, authentication.secret, {
                expiresIn: authentication.expiresIn,

            }),
        })
    }
}

export default new SessionController();