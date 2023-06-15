<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Auth;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Hash;
use Modules\Role\Entities\Role_user;
use Mail;
use App\Mail\UserRegisteredFromSocial;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
class SocialiteLoginController extends Controller
{

    //Google Login
    CONST GOOGLE_TYPE = 'google';

    public function redirectToGoogle(){
        $url = Socialite::with(static::GOOGLE_TYPE)->with(["prompt" => "select_account"])->redirect()->getTargetUrl();
        return response()->json([
            "url"=>$url
        ]);
    }

    public function apiSocialLogin(Request $request)
    {
        try {
            DB::beginTransaction();
            $validation = Validator::make($request->all(), [
                'name' => "nullable|string|max:191",
                'password' => "required|string|max:191",
                "email" => "nullable|email|max:191",
                "oauth_id" => "required|string|max:191",
                "oauth_type" => "required|string|in:google,facebook,apple",
                "image" => "nullable|url",
            ]);

            if ($validation->fails()) {
                $errors = $validation->errors()->all()->map(function ($message) {
                    return $message;
                });

                return response()->json([
                    "status" => false,
                    "status_code" => 500,
                    "message" => "Something went wrong while Login",
                    "error" => $errors,
                ], 500);
            }

            $userExisted = User::where('email',$request->email)->first();
            if($userExisted){

                Auth::login($userExisted);
                $token = auth()->user()->createToken('authToken')->accessToken;
                return response()->json([
                    "status" => "true",
                    "message" => "success",
                    'token' => $token,
                    'user' => auth()->user()
                  ], 200);

            }else{
                $newUser = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'oauth_id' => $request->oauth_id,
                    'oauth_type' => $request->oauth_type,
                    'password' => Hash::make($request->oauth_id),
                    'avatar' => $request->url,
                    'publish' => 1,
                    'verified' => 1,
                    'vendor_type' => 'approved'
                ]);

                if($newUser){
                    $customer = User::where('email', $request->email)->first();
                }

                $role_data = [
                    'role_id' => 4,
                    'user_id' => $customer->id
                ];
                Role_user::create($role_data);

                Mail::to($customer->email)->send(new UserRegisteredFromSocial($customer));

                Auth::login($newUser);
                
                $token = auth()->user()->createToken('authToken')->accessToken;
                DB::commit();
                return response()->json([
                    "status" => "true",
                    "message" => "success",
                    'token' => $token,
                    'user' => auth()->user()
                  ], 200);
            }
        } catch (\Throwable $th) {
            DB::rollback();
            return response()->json([
                "status" => false,
                "status_code" => 500,
                "message" => "Something went wrong while Login",
                "error" => $th->getMessage(),
            ], 500);
        }
    }

    public function handleGoogleCallBack(){
        try{
            $user = Socialite::driver(static::GOOGLE_TYPE)->stateless()->user();

            $userExisted = User::where('email',$user->email)->first();

            if($userExisted){

                Auth::login($userExisted);
                $token = auth()->user()->createToken('authToken')->accessToken;
                return response()->json([
                    "status" => "true",
                    "message" => "success",
                    'token' => $token,
                    'user' => auth()->user()
                  ], 200);

            }else{
                $newUser = User::create([
                    'name' => $user->name,
                    'email' => $user->email,
                    'oauth_id' => $user->id,
                    'oauth_type' => static::GOOGLE_TYPE,
                    'password' => Hash::make($user->id),
                    'avatar' => $user->getAvatar(),
                    'publish' => 1,
                    'verified' => 1,
                    'vendor_type' => 'approved'
                ]);

                if($newUser){
                    $customer = User::where('email', $user->email)->first();
                }

                $role_data = [
                    'role_id' => 4,
                    'user_id' => $customer->id
                ];
                Role_user::create($role_data);

                Mail::to($customer->email)->send(new UserRegisteredFromSocial($customer));

                Auth::login($newUser);
                
                $token = auth()->user()->createToken('authToken')->accessToken;
                return response()->json([
                    "status" => "true",
                    "message" => "success",
                    'token' => $token,
                    'user' => auth()->user()
                  ], 200);
            }
        }catch(Exception $e){
            dd($e);
        }
    }

    //Facebook login

    CONST FACEBOOK_TYPE = 'facebook';

    public function redirectToFacebook(){
        $url = Socialite::driver(static::FACEBOOK_TYPE)->with(["prompt" => "select_account"])->redirect()->getTargetUrl();
       return response()->json([
        "url"=>$url
    ]);
    }

    public function handleFacebookCallBack(){
        try{
            $user = Socialite::driver(static::FACEBOOK_TYPE)->stateless()->user();
            if(!empty($user->getEmail())){
                $userExisted = User::where('email',$user->email)->first();
                if($userExisted){
                    Auth::login($userExisted);
                    $token = auth()->user()->createToken('authToken')->accessToken;
                    return response()->json([
                        "status" => "true",
                        "message" => "success",
                        'token' => $token,
                        'user' => auth()->user()
                      ], 200);
    
                }else{
                    $newUser = User::create([
                        'name' => $user->name,
                        'email' => $user->email,
                        'oauth_id' => $user->id,
                        'oauth_type' => static::FACEBOOK_TYPE,
                        'password' => Hash::make($user->id),
                        'avatar' => $user->getAvatar(),
                        'publish' => 1,
                        'verified' => 1,
                        'vendor_type' => 'approved'
                    ]);
    
                    if($newUser){
                        $customer = User::where('email', $user->email)->first();
                    }
    
                    $role_data = [
                        'role_id' => 4,
                        'user_id' => $customer->id
                    ];
                    Role_user::create($role_data);
    
                    Mail::to($customer->email)->send(new UserRegisteredFromSocial($customer));
    
                    Auth::login($newUser);
                    
                    $token = auth()->user()->createToken('authToken')->accessToken;
                    return response()->json([
                        "status" => "true",
                        "message" => "success",
                        'token' => $token,
                        'user' => auth()->user()
                      ], 200);
                }
            }else{
                return response()->json([
                    "status" => "false",
                    "message" => "unsuccess",
                  ], 402);
            }
           
        }catch(Exception $e){
            DB::rollback();
            return response([
                'message' => $e->getMessage()
            ],400);
        }
    }

    protected function deleteMainUserImage(User $user)
    {
        if ($user->image) {
            $this->imageService->unlinkImage($user->image);
        }
    }
}
