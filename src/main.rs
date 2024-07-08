use std::time::Instant ;

mod schnorr;
fn main() {
    let message = "hello".as_bytes() ;
    let start = Instant::now();
    let (sk,pk,g) = schnorr::keyGen() ;
    let duration = start.elapsed();
    println!("time elapsed in key gen is: {:?}", duration) ;
    
    let start = Instant::now();
    #[allow(non_snake_case)]
    let (R, u) = schnorr::sign(&message, &sk, &g) ;
    let duration = start.elapsed();
    println!("time elapsed in signing is: {:?}", duration) ;

    let start = Instant::now();
    let b = schnorr::verify(&R, &u, &pk, &message, &g) ;
    let duration = start.elapsed();
    println!("time elapsed in verifying is: {:?}", duration) ;
    if b {
        println!("test passed") ;
    }
    else {
        println!("uh-oh!!")
    }
}
