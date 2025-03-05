import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:google_sign_in/google_sign_in.dart';

class AuthService {
  final FirebaseAuth _auth = FirebaseAuth.instance;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final GoogleSignIn _googleSignIn = GoogleSignIn();

  // Register user with email and password and store in database
  Future<String?> registerUserWithEmail({required String email, required String password}) async {
    try {
      final credential = await FirebaseAuth.instance.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );

      // Store user in Firestore database
      await _firestore.collection('users').doc(credential.user!.uid).set({
        'uid': credential.user!.uid,
        'email': email,
        'createdAt': DateTime.now(),
      });

      return 'Success';
    } on FirebaseAuthException catch (e) {
      if (e.code == 'weak-password') {
        return ('The password provided is too weak.');
      } else if (e.code == 'email-already-in-use') {
        return ('The account already exists for that email.');
      } else {
        return e.message;
      }
    } catch (e) {
      return e.toString();
    }
  }

  // User login with email & password
  Future<String?> loginUserWithEmail({required String email, required String password}) async {
    try {
      final credential = await FirebaseAuth.instance.signInWithEmailAndPassword(
        email: email,
        password: password
      );
      return 'Success';
    } on FirebaseAuthException catch (e) {
      if (e.code == 'user-not-found') {
        return ('No user found for that email.');
      } else if (e.code == 'wrong-password') {
        return ('Wrong password provided for that user.');
      } else {
        return e.message;
      }
    }
  }

  // Sign in with Google
  Future<UserCredential> signInWithGoogle() async {
    // Trigger the authentication flow
    final GoogleSignInAccount? googleUser = await GoogleSignIn().signIn();

    // Obtain the auth details from the request
    final GoogleSignInAuthentication? googleAuth = await googleUser?.authentication;

    // Create a new credential
    final credential = GoogleAuthProvider.credential(
      accessToken: googleAuth?.accessToken,
      idToken: googleAuth?.idToken,
    );

    UserCredential userCredential = await _auth.signInWithCredential(credential);
    User? user = userCredential.user;

    // Check if user exists in Firestore database already
    DocumentSnapshot userDoc = await _firestore.collection('users').doc(user!.uid).get();
    if(!userDoc.exists) {
      // New user, store user in database
      await _firestore.collection('users').doc(user.uid).set({
        'uid': user.uid,
        'email': user.email,
        'fullName': user.displayName ?? '',
        'photoURL': user.photoURL ?? '',
        'createdAt': DateTime.now(),
      });
    }
    
    return await FirebaseAuth.instance.signInWithCredential(credential);
  }

  // Logout User
  Future<void> logoutUser() async {
    await _auth.signOut();
    await _googleSignIn.signOut();
  }

  User? getCurrentUser() {
    return _auth.currentUser;
  }
}