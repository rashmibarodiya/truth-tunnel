import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import bcrypt from "bcryptjs";
import dbConnect from "@/lib/dbConnect";
import UserModel from "@/model/User";

export const authOptions: NextAuthOptions = {
  providers: [
    // Google Provider
    GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID ?? "",
        clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
        async profile(profile) {
          await dbConnect();
          
          try {
            // Find or create user in the database
            if (!profile || !profile.email) {
              console.log("Profile is null or does not contain email.")
                throw new Error("Profile is null or does not contain email.");
              }
              
            console.log("everthing fines yet to create user",profile)
            let user = await UserModel.findOne({ email: profile.email });
     
            // If user doesn't exist, create it
            if (!user) {
              user = new UserModel({
                email: profile.email,
                username: profile.email, // Default username to email in case of google authentication
                isVerified: true, // assuming that email is already verfied by google provider
                isAcceptingMessage: true,
                messages: []
              });
              
              await user.save();
              console.log("User created:", user);
            } else {
              console.log("User already existed:", user);
            }
            
            // Return user with id field, which is required by NextAuth's User type
            return {
              id: user._id.toString(),
              email: user.email,
              username: user.username,
              isVerified: user.isVerified,
              isAcceptingMessage: user.isAcceptingMessage
            };
          } catch (error) {
            console.error("Error in Google Provider profile method:", error);
            throw new Error("Unable to process user profile.");
          }
        }
      }),
      
    // Credentials Provider
    CredentialsProvider({
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials: any): Promise<any> {
        await dbConnect();
        const user = await UserModel.findOne({
          $or: [
            { email: credentials.identifier },
            { username: credentials.identifier }
          ]
        });
        if (!user) {
          throw new Error("No user found with this email");
        }
        if (!user.isVerified) {
          throw new Error("Please verify your account before login");
        }
        const isPasswordCorrect = await bcrypt.compare(credentials.password, user.password);
        if (!isPasswordCorrect) {
          throw new Error("Incorrect password");
        }
        return user;
      }
    })
  ],
  pages: {
    signIn: "/sign-in",
    
  },
  session: {
    strategy: "jwt"
  },
  callbacks: {
    async jwt({ token, user }) {

       
      if (user) {
        token._id = user.id?.toString();
        token.isVerified = user.isVerified;
        token.isAcceptingMessage = user.isAcceptingMessage;
        token.username = user.username;
      }
      return token;
    },
    async session({ session, token }) {
        
      if (token) {
        session.user._id = token._id;
        session.user.isVerified = token.isVerified;
        session.user.isAcceptingMessage = token.isAcceptingMessage;
        session.user.username = token.username;
      }
     
      return session;
    }
  },
  secret: process.env.NEXTAUTH_SECRET
};
