//
// Created by jojo on 3/13/23.
//
#include "examples.h"

using namespace std;
using namespace seal;

void bfv_performance(SEALContext context)
{
    print_example_banner("Test: bfv_performance");

    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);
    cout << endl;

    auto &parms = context.first_context_data()->parms();
    auto &plain_modulus = parms.plain_modulus();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        /*
        Generate relinearization keys.
        */
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.key_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        /*
        Generate Galois keys. In larger examples the Galois keys can use a lot of
        memory, which can be a problem in constrained systems. The user should
        try some of the larger runs of the test and observe their effect on the
        memory pool allocation size. The key generation can also take a long time,
        as can be observed from the print-out.
        */
        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    /*
    These will hold the total times used by each operation.
    */
    chrono::microseconds time_batch_sum(0);
    chrono::microseconds time_unbatch_sum(0);
    chrono::microseconds time_encrypt_sum(0);
    chrono::microseconds time_decrypt_sum(0);
    chrono::microseconds time_add_sum(0);
    chrono::microseconds time_multiply_sum(0);
    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_square_sum(0);
    chrono::microseconds time_relinearize_sum(0);
    chrono::microseconds time_rotate_rows_one_step_sum(0);
    chrono::microseconds time_rotate_rows_random_sum(0);
    chrono::microseconds time_rotate_columns_sum(0);
    /*
    How many times to run the test?
    */
    long long count = 10;

    /*
    Populate a vector of values to batch.
    */
    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_vector.push_back((i & size_t(0x1)) + 1);
    }

    cout << "Running tests ";
    for (size_t i = 0; i < static_cast<size_t>(count); i++)
    {
        /*
        [Batching]
        There is nothing unusual here. We batch our random plaintext matrix
        into the polynomial. Note how the plaintext we create is of the exactly
        right size so unnecessary reallocations are avoided.
        */
        Plaintext plain(poly_modulus_degree, 0);
        Plaintext plain1(poly_modulus_degree, 0);
        Plaintext plain2(poly_modulus_degree, 0);
        time_start = chrono::high_resolution_clock::now();
        batch_encoder.encode(pod_vector, plain);
        time_end = chrono::high_resolution_clock::now();
        time_batch_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Unbatching]
        We unbatch what we just batched.
        */
        vector<uint64_t> pod_vector2(slot_count);
        time_start = chrono::high_resolution_clock::now();
        batch_encoder.decode(plain, pod_vector2);
        time_end = chrono::high_resolution_clock::now();
        time_unbatch_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        if (pod_vector2 != pod_vector)
        {
            throw runtime_error("Batch/unbatch failed. Something is wrong.");
        }

        /*
        [Encryption]
        We make sure our ciphertext is already allocated and large enough
        to hold the encryption with these encryption parameters. We encrypt
        our random batched matrix here.
        */
        Ciphertext encrypted(context);
        time_start = chrono::high_resolution_clock::now();
        encryptor.encrypt(plain, encrypted);
        time_end = chrono::high_resolution_clock::now();
        time_encrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Decryption]
        We decrypt what we just encrypted.
        */
        time_start = chrono::high_resolution_clock::now();
        decryptor.decrypt(encrypted, plain2);
        time_end = chrono::high_resolution_clock::now();
        time_decrypt_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        if (plain2 != plain)
        {
            throw runtime_error("Encrypt/decrypt failed. Something is wrong.");
        }

        /*
        [Add]
        We create two ciphertexts and perform a few additions with them.
        */
        Ciphertext encrypted1(context);
        batch_encoder.encode(vector<uint64_t>(slot_count, i), plain1);
        encryptor.encrypt(plain1, encrypted1);
        Ciphertext encrypted2(context);
        batch_encoder.encode(vector<uint64_t>(slot_count, i + 1), plain2);
        encryptor.encrypt(plain2, encrypted2);
        time_start = chrono::high_resolution_clock::now();
        evaluator.add_inplace(encrypted1, encrypted1);
        evaluator.add_inplace(encrypted2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_add_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Multiply]
        We multiply two ciphertexts. Since the size of the result will be 3,
        and will overwrite the first argument, we reserve first enough memory
        to avoid reallocating during multiplication.
        */
        encrypted1.reserve(3);
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Multiply Plain]
        We multiply a ciphertext with a random plaintext. Recall that
        multiply_plain does not change the size of the ciphertext so we use
        encrypted2 here.
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(encrypted2, plain);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        /*
        [Square]
        We continue to use encrypted2. Now we square it; this should be
        faster than generic homomorphic multiplication.
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.square_inplace(encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        if (context.using_keyswitching())
        {
            /*
            [Relinearize]
            Time to get back to encrypted1. We now relinearize it back
            to size 2. Since the allocation is currently big enough to
            contain a ciphertext of size 3, no costly reallocations are
            needed in the process.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.relinearize_inplace(encrypted1, relin_keys);
            time_end = chrono::high_resolution_clock::now();
            time_relinearize_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Rows One Step]
            We rotate matrix rows by one step left and measure the time.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_rows_inplace(encrypted, 1, gal_keys);
            evaluator.rotate_rows_inplace(encrypted, -1, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_rows_one_step_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            ;

            /*
            [Rotate Rows Random]
            We rotate matrix rows by a random number of steps. This is much more
            expensive than rotating by just one step.
            */
            size_t row_size = batch_encoder.slot_count() / 2;
            // row_size is always a power of 2
            int random_rotation = static_cast<int>(rd() & (row_size - 1));
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_rows_inplace(encrypted, random_rotation, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_rows_random_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Columns]
            Nothing surprising here.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_columns_inplace(encrypted, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_columns_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        }

        cout << ".";
        cout.flush();
    }

    cout << " Done" << endl << endl;
    cout.flush();

    auto avg_batch = time_batch_sum.count() / count;
    auto avg_unbatch = time_unbatch_sum.count() / count;
    auto avg_encrypt = time_encrypt_sum.count() / count;
    auto avg_decrypt = time_decrypt_sum.count() / count;
    auto avg_add = time_add_sum.count() / (3 * count);
    auto avg_multiply = time_multiply_sum.count() / count;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_square = time_square_sum.count() / count;
    auto avg_relinearize = time_relinearize_sum.count() / count;
    auto avg_rotate_rows_one_step = time_rotate_rows_one_step_sum.count() / (2 * count);
    auto avg_rotate_rows_random = time_rotate_rows_random_sum.count() / count;
    auto avg_rotate_columns = time_rotate_columns_sum.count() / count;

    cout << "Average batch: " << avg_batch << " microseconds" << endl;
    cout << "Average unbatch: " << avg_unbatch << " microseconds" << endl;
    cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
    cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
    cout << "Average add: " << avg_add << " microseconds" << endl;
    cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
    cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
    cout << "Average square: " << avg_square << " microseconds" << endl;
    if (context.using_keyswitching())
    {
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rotate rows one step: " << avg_rotate_rows_one_step << " microseconds" << endl;
        cout << "Average rotate rows random: " << avg_rotate_rows_random << " microseconds" << endl;
        cout << "Average rotate columns: " << avg_rotate_columns << " microseconds" << endl;
    }
    cout.flush();
}

void bfv_multiplication_comparison(SEALContext context)
{
    print_example_banner("Test: bfv_multiplication_comparison");

    auto &context_data = *context.key_context_data();
    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);
    cout << endl;

    auto &parms = context.first_context_data()->parms();
    auto plain_modulus = parms.plain_modulus().value();
    auto poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context.using_keyswitching())
    {
        /*
        Generate relinearization keys.
        */
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_relin_keys(relin_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context.key_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        /*
        Generate Galois keys. In larger examples the Galois keys can use a lot of
        memory, which can be a problem in constrained systems. The user should
        try some of the larger runs of the test and observe their effect on the
        memory pool allocation size. The key generation can also take a long time,
        as can be observed from the print-out.
        */
        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        keygen.create_galois_keys(gal_keys);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    chrono::microseconds time_multiply_plain_sum(0);
    chrono::microseconds time_dot_product_plain_sum(0);

    long long count = 1;

    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t> pod_vector;
    std::random_device rd; // 获取真正的随机种子
    std::mt19937 gen(rd()); // 使用mt19937作为随机数生成器
    std::uniform_int_distribution<> dis(0, 99);
    for (size_t i = 0; i < slot_count / 2; i++)
    {
        //        pod_vector.push_back(dis(gen));
        pod_vector.push_back((i & size_t(0x1)) + 90);
    }
    vector<uint64_t> tmp(poly_modulus_degree);
    for (int i = 0; i < 3; i++)
    {
        tmp[i] = i + 1;
    }
    cout << "pod_vector: " << endl;
    print_vector(pod_vector);
    vector<uint64_t> plain_vector = pod_vector;
    cout << "plain_vector: " << endl;
    print_vector(plain_vector);

    cout << "Running tests ..." << endl;
    for (size_t i = 0; i < static_cast<size_t>(count); i++)
    {
        Plaintext plain(poly_modulus_degree, 0);
        Plaintext plain1(poly_modulus_degree, 0);
        Plaintext plain2;
        plain2.parms_id() = seal::parms_id_zero;
        plain2.resize(poly_modulus_degree);

        batch_encoder.encode(pod_vector, plain);
        batch_encoder.encode(plain_vector, plain);

        Ciphertext mult_result(context);
        encryptor.encrypt(plain, mult_result);
        /*
        [Multiply Plain]
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(mult_result, plain);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

        Plaintext plain_result;
        vector<uint64_t> pod_result;

        decryptor.decrypt(mult_result, plain_result);
        batch_encoder.decode(plain_result, pod_result);
        //        print_line(__LINE__);
        //        cout << "Decrypt and decode result." << endl;
        //        cout << "    + Result plaintext ...... Correct." << endl;
        //        print_vector(pod_result);

        /*
        [Rotation Dot Product Plain]
//        */
        //        Ciphertext dot_product_result = mult_result;
        //        Plaintext dot_product_plain_result;
        //        time_start = chrono::high_resolution_clock::now();
        //        for (int j = 1; j < pod_vector.size(); j++)
        //        {
        //            evaluator.rotate_rows(mult_result, -j, gal_keys, mult_result);
        //            evaluator.add(dot_product_result, mult_result, dot_product_result);
        //        }
        //        time_end = chrono::high_resolution_clock::now();
        //        time_dot_product_plain_sum += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        //
        //        vector<uint64_t> dot_result;
        //        decryptor.decrypt(dot_product_result, dot_product_plain_result);
        //        batch_encoder.decode(dot_product_plain_result, dot_result);
        //        uint64_t res = dot_product(pod_vector.begin(), pod_vector.end(), plain_vector.begin(), 0);
        //        cout << "Dot product: " << res % plain_modulus << endl;
        //
        /*
        [Cheetah Dot Product Plain]
        */
        seal::util::modulo_poly_coeffs(tmp.data(), tmp.size(), plain_modulus, plain2.data());
        //        std::fill_n(plain2.data() + pod_vector.size(), plain2.coeff_count() - pod_vector.size(), 0);
        print_vector(tmp);
        Ciphertext this_ct(context);

        // cout << "this_ct.coeff_modulus_size(): " << this_ct.coeff_modulus_size() << endl;
        Plaintext dot_product_plain_result;
        encryptor.encrypt(plain2, this_ct);
        evaluator.multiply_plain_inplace(this_ct, plain2);

        decryptor.decrypt(this_ct, dot_product_plain_result);

        cout << " dot_product_plain_result: " << dot_product_plain_result.to_string() << endl;

        auto this_ct_ptr = this_ct.data();

        for (size_t index = 0; index < poly_modulus_degree; ++index)
        {
            if (index < 3 && index % 2 == 0)
            {
                continue;
            }

            this_ct_ptr[index] = 0;
        }
        for (size_t index = 0; index < poly_modulus_degree; ++index)
        {
            cout << this_ct_ptr[index] << " ";
        }

        cout << endl;
        cout.flush();
    }
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_dot_product_plain = (time_dot_product_plain_sum.count() + time_multiply_plain_sum.count()) / count;
    cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
    cout << "Average dot_product plain: " << avg_dot_product_plain << " microseconds" << endl;
}

void cheetah_bfv_conv()
{
    print_example_banner("Example: cheetah_bfv_conv");
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context = parms;

    // bfv_performance(context);

    cout << endl;
    bfv_multiplication_comparison(context);
}

void ckks_poly(SEALContext context)
{
    auto &parms = context.first_context_data()->parms();
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    vector<double> input{ 1.1, 2.2, 3.3 };
    cout << "Input vector: " << endl;
    print_vector(input);
    Plaintext plain1, plain2;
    double scale = pow(2.0, 30);
    print_line(__LINE__);
    cout << "Embed input vector into plaintext." << endl;
    encoder.embed_vec2plaintext(input, scale, plain1);
    encoder.embed_vec2plaintext(input, scale, plain2);

    Ciphertext encrypted;
    print_line(__LINE__);
    cout << "Encrypt input vector." << endl;
    encryptor.encrypt(plain1, encrypted);

    print_line(__LINE__);
    cout << "Compute encrypted multiply plain2." << endl;
    evaluator.multiply_plain_inplace(encrypted, plain2);

    Plaintext plain_result;
    cout << "Decrypt result." << endl;
    decryptor.decrypt(encrypted, plain_result);

    // encoder.extract_vec2plaintext(plain_result, output);
    //    for (int i = 0; i < output.size(); ++i)
    //    {
    //        std::cout << "Coefficient " << i << ": " << output[i] << std::endl;
    //    }
    //    vector<double> result{ 1.1, 4.4, 11.44, 14.52, 10.89 };
    //    cout << "result vector: " << endl;
    //    print_vector(result);
    //
    Plaintext plain3;
    print_line(__LINE__);
    cout << "Embed input vector into plaintext and decode." << endl;
    encoder.embed_vec2plaintext(input, scale, plain3);

    vector<double> output;
    encoder.extract_vec2plaintext(plain3, output);
    cout << "Decode result vector." << endl;
    //
    //    vector<double> output2;
    //    encoder.extract_vec2plaintext(plain_result, output2);

    //    for (int i = 0; i < output.size(); ++i)
    //    {
    //        if (output[i] != 0)
    //        {
    //            std::cout << "Coefficient " << i << ": " << output[i] << std::endl;
    //        }
    //    }
}
void ckks_encode_decode()
{
    print_example_banner("Example: Encoders / CKKS Encoder");

    /*
    [CKKSEncoder] (For CKKS scheme only)

    In this example we demonstrate the Cheon-Kim-Kim-Song (CKKS) scheme for
    computing on encrypted real or complex numbers. We start by creating
    encryption parameters for the CKKS scheme. There are two important
    differences compared to the BFV scheme:

        (1) CKKS does not use the plain_modulus encryption parameter;
        (2) Selecting the coeff_modulus in a specific way can be very important
            when using the CKKS scheme. We will explain this further in the file
            `ckks_basics.cpp'. In this example we use CoeffModulus::Create to
            generate 5 40-bit prime numbers.
    */
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));

    /*
    We create the SEALContext as usual and print the parameters.
    */
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    /*
    Keys are created the same way as for the BFV scheme.
    */
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    /*
    We also set up an Encryptor, Evaluator, and Decryptor as usual.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    To create CKKS plaintexts we need a special encoder: there is no other way
    to create them. The BatchEncoder cannot be used with the
    CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
    Plaintext objects, which can subsequently be encrypted. At a high level this
    looks a lot like what BatchEncoder does for the BFV scheme, but the theory
    behind it is completely different.
    */
    CKKSEncoder encoder(context);

    /*
    In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes
    one real or complex number. This should be contrasted with BatchEncoder in
    the BFV scheme, where the number of slots is equal to poly_modulus_degree
    and they are arranged into a matrix with two rows.
    */
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /*
    We create a small vector to encode; the CKKSEncoder will implicitly pad it
    with zeros to full size (poly_modulus_degree / 2) when encoding.
    */
    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
    will be scaled up by the parameter `scale'. This is necessary since even in
    the CKKS scheme the plaintext elements are fundamentally polynomials with
    integer coefficients. It is instructive to think of the scale as determining
    the bit-precision of the encoding; naturally it will affect the precision of
    the result.

    In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
    plain_modulus), so the scaled message must not get too close to the total size
    of coeff_modulus. In this case our coeff_modulus is quite large (200 bits) so
    we have little to worry about in this regard. For this simple example a 30-bit
    scale is more than enough.
    */
    Plaintext plain;
    double scale = pow(2.0, 30);
    print_line(__LINE__);
    cout << "Encode input vector." << endl;
    encoder.encode(input, scale, plain);

    /*
    We can instantly decode to check the correctness of encoding.
    */
    vector<double> output;
    cout << "    + Decode input vector ...... Correct." << endl;
    encoder.decode(plain, output);
    print_vector(output);
}

// void ckks_multiplication_comparison(SEALContext context)
//{
//     chrono::high_resolution_clock::time_point time_start, time_end;
//
//     print_parameters(context);
//     cout << endl;
//
//     auto &parms = context.first_context_data()->parms();
//     size_t poly_modulus_degree = parms.poly_modulus_degree();
//     auto plain_modulus = parms.plain_modulus().value();
//     cout << "Generating secret/public keys: ";
//     KeyGenerator keygen(context);
//     cout << "Done" << endl;
//
//     auto secret_key = keygen.secret_key();
//     PublicKey public_key;
//     keygen.create_public_key(public_key);
//
//     RelinKeys relin_keys;
//     GaloisKeys gal_keys;
//     chrono::microseconds time_diff;
//     if (context.using_keyswitching())
//     {
//         cout << "Generating relinearization keys: ";
//         time_start = chrono::high_resolution_clock::now();
//         keygen.create_relin_keys(relin_keys);
//         time_end = chrono::high_resolution_clock::now();
//         time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//         cout << "Done [" << time_diff.count() << " microseconds]" << endl;
//
//         if (!context.first_context_data()->qualifiers().using_batching)
//         {
//             cout << "Given encryption parameters do not support batching." << endl;
//             return;
//         }
//
//         cout << "Generating Galois keys: ";
//         time_start = chrono::high_resolution_clock::now();
//         keygen.create_galois_keys(gal_keys);
//         time_end = chrono::high_resolution_clock::now();
//         time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
//         cout << "Done [" << time_diff.count() << " microseconds]" << endl;
//     }
//     Encryptor encryptor(context, public_key);
//     Decryptor decryptor(context, secret_key);
//     Evaluator evaluator(context);
//     CKKSEncoder ckks_encoder(context);
//
//     chrono::microseconds time_multiply_plain_sum(0);
//     chrono::microseconds time_dot_product_plain_sum(0);
//
//     cout << poly_modulus_degree << " & " << ckks_encoder.slot_count() << endl;
//     long long count = 1;
//     vector<double> pod_vector(ckks_encoder.slot_count());
//     vector<double> pod_vector2(ckks_encoder.slot_count());
//
//     for (int i = 0; i < 3; i++)
//     {
//         pod_vector[i] = i + 1.0;
//     }
//     cout << "Running tests ..." << endl;
//
//     for (long long i = 0; i < count; i++)
//     {
//         //        Plaintext plain(parms.poly_modulus_degree() * parms.coeff_modulus().size(), 0);
//         //
//         //        double scale = sqrt(static_cast<double>(parms.coeff_modulus().back().value()));
//         //        ckks_encoder.encode(pod_vector, scale, plain);
//         //        std::stringstream ss;
//         //        plain.save(ss);
//         //        std::string str_output = ss.str();
//         //
//         //        std::cout << "NTT transformed plaintext: " << std::endl;
//         //        std::cout << "Coefficients in HEX: " << std::endl;
//         //        for (size_t i = 0; i < plain.coeff_count(); i++)
//         //        {
//         //            std::stringstream hex_stream;
//         //            hex_stream << std::hex << plain[i];
//         //            std::cout << "Coefficient " << i << ": " << hex_stream.str() << std::endl;
//         //        }
//         //        ckks_encoder.decode(plain, pod_vector2);
//         //        for (auto c : pod_vector2)
//         //        {
//         //            cout << c << " ";
//         //        }
//         //        cout << endl;
//         Plaintext plain2;
//         plain2.parms_id() = seal::parms_id_zero;
//         plain2.resize(poly_modulus_degree);
//         seal::util::modulo_poly_coeffs(pod_vector.data(), pod_vector.size(), plain_modulus, plain2.data());
//         Ciphertext this_ct(context);
//         Plaintext dot_product_plain_result;
//         encryptor.encrypt(plain2, this_ct);
//         evaluator.multiply_plain_inplace(this_ct, plain2);
//         decryptor.decrypt(this_ct, dot_product_plain_result);
//
//         cout << " dot_product_plain_result: " << dot_product_plain_result.to_string() << endl;
//         auto this_ct_ptr = this_ct.data();
//
//         for (size_t index = 0; index < poly_modulus_degree; ++index)
//         {
//             if (index < 3 && index % 2 == 0)
//             {
//                 continue;
//             }
//
//             this_ct_ptr[index] = 0;
//         }
//         for (size_t index = 0; index < poly_modulus_degree; ++index)
//         {
//             cout << this_ct_ptr[index] << " ";
//         }
//
//         cout << endl;
//
//         decryptor.decrypt(this_ct, dot_product_plain_result);
//
//         cout << " dot_product_plain_result: " << dot_product_plain_result.to_string() << endl;
//
//         cout << endl;
//         cout.flush();
//     }
// }
void cheetah_ckks_conv()
{
    print_example_banner("Example: cheetah_ckks_conv");
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    //    parms.set_poly_modulus_degree(poly_modulus_degree);
    //    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    SEALContext context = parms;
    cout << endl;
    // ckks_multiplication_comparison(context);
    ckks_poly(context);
}
void conv_performance_test()
{
    print_example_banner("Example: Conv Performance Test");

    while (true)
    {
        cout << endl;
        cout << "Select a scheme (and optionally poly_modulus_degree):" << endl;
        cout << "  1. BFV with default degrees" << endl;
        cout << "  2. CKKS with default degrees" << endl;
        cout << "  0. Back to main menu" << endl;

        int selection = 0;
        cout << endl << "> Run performance test (1 ~ 2) or go back (0): ";
        //        if (!(cin >> selection))
        //        {
        //            cout << "Invalid option." << endl;
        //            cin.clear();
        //            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        //            continue;
        //        }

        // selection = 2;
        cin >> selection;
        switch (selection)
        {
        case 1:
            cheetah_bfv_conv();
            break;

        case 2:
            cheetah_ckks_conv();
            // ckks_encode_decode();
            return;

        case 0:
            cout << endl;
            return;

        default:
            cout << "Invalid option." << endl;
        }
    }
}