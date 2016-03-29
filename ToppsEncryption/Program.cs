using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;


namespace ToppsEncryption
{
    class ToppsEncryptionMethod
    {
        public byte[] OTEMKey { get; set; }
        public byte[] CTEMKey { get; set; }
        public void CTEM_Encrypt(string MessageLocation, string OutputFile)
        {

            //create crypto service providers
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            AesCryptoServiceProvider Aes = new AesCryptoServiceProvider();
            // read message in from file
            byte[] encrypt1 = File.ReadAllBytes(MessageLocation);
            int type1 = 0, type2 = 0;
            byte[] iv1, iv2;
            //check to see if key length is 0, if it is generate a random key
            if(CTEMKey.Length == 0)
            {
                CTEM_KeyGen();
            }
            //read key in
            byte[] keyin = CTEMKey;
            int keylength = 0;
            //copy key in
            byte[] pull = keyin;
            //resize array to 4 to read first length byte
            Array.Resize(ref pull, 4);
            //read firse length byte
            byte convert = pull[0];
            //convert byte to int
            keylength = Convert.ToInt32(convert);
            //define key1 as a byte array of fist key length
            byte[] key1 = new byte[keylength];
            //copy key over
            System.Buffer.BlockCopy(keyin, 1, key1, 0, keylength);
            //overwrite pull with new key length info
            System.Buffer.BlockCopy(keyin, 1 + keylength, pull, 0, 4);
            //convert value to int
            convert = pull[0];
            keylength = Convert.ToInt32(convert);
            //define key2 as a byte array of second key length and copy key over
            byte[] key2 = new byte[keylength];
            System.Buffer.BlockCopy(keyin, 2 + key1.Length, key2, 0, keylength);
            //if key length is 25 then is tdes
            if (key1.Length == 25)
            {
                //generates random iv for iv1
                tdes.GenerateIV();
                iv1 = tdes.IV;
            }
            //otherwise is Aes
            else
            {
                //generates random iv for iv1
                Aes.GenerateIV();
                iv1 = Aes.IV;
            }
            //if tdes then assign iv2 to 8 bytes and copy last 8 bytes of keyin to iv2
            if (key2.Length == 25)
            {
                iv2 = new byte[8];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length, iv2, 0, 8);
            }
            //if Aes then assign iv2 to 16 bytes and copy last 16 bytes of keyin to iv2
            else
            {
                iv2 = new byte[16];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length, iv2, 0, 16);
            }
            //if key2 is tdes resize to 24 bytes, last bit was just to check to see if it is tdes and assign type2 to 2
            if (key2.Length == 25)
            {
                type2 = 2;
                Array.Resize(ref key2, key2.Length - 1);
            }
            //if Aes assign type2 to 1
            else
            {
                type2 = 1;
            }
            //if key1 is tdes resize to 24 bytes, last bit was just to check to see if it is tdes and assign type1 to 2
            if (key1.Length == 25)
            {
                type1 = 2;
                Array.Resize(ref key1, key1.Length - 1);
            }
            //if Aes assign type1 to 1
            else
            {
                type1 = 1;
            }
            //call encrypt function with key1 and iv1
            encrypt1 = Encrypt(encrypt1, key1, iv1, type1, 0);
            //assign new byte buffer and add iv1 to front of first message
            byte[] encrypt2 = new byte[encrypt1.Length + iv1.Length];
            System.Buffer.BlockCopy(iv1, 0, encrypt2, 0, iv1.Length);
            System.Buffer.BlockCopy(encrypt1, 0, encrypt2, iv1.Length, encrypt1.Length);
            //encrypt second message again with key2 and iv2
            encrypt2 = Encrypt(encrypt2, key2, iv2, type2, 0);
            //write to output file
            File.WriteAllBytes(OutputFile, encrypt2);
        }

        public void OTEM_Encrypt(string Message_Location, string OutputFile)
        {
            #region
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            AesCryptoServiceProvider Aes = new AesCryptoServiceProvider();
            Aes.KeySize = 256;
            Random rnd = new Random();
            byte[] encrypt1 = File.ReadAllBytes(Message_Location);
            int size = 0;
            if(encrypt1.Length < int.MaxValue)
            {
                size = encrypt1.Length;
            }
            else
            {
                size = int.MaxValue;
            }

            int tracker = 0, arrayptr = 0, i = 0, j = 0, keychoice = rnd.Next(1, 4);
            int embedmarker = rnd.Next(1, size);
            int embedchar = rnd.Next(0, 65535);
            int typeselect = 0, type1 = 0, type2 = 0;
            char embeddedchar = (char)embedchar;

            byte[] arr;
            byte[] temp = new byte[8];
            byte[] key1 = Aes.Key, key2 = Aes.Key, iv1 = Aes.Key, iv2 = Aes.Key;
            int endembed = (size / embedmarker);
            for (i = 0; i < 2; i++)
            {
                typeselect = rnd.Next(1, 3);
                if (i == 0 && typeselect == 1)
                {
                    keychoice = rnd.Next(1, 4);
                    if (keychoice == 3)
                    {
                        Aes.KeySize = 256;
                    }
                    else if (keychoice == 2)
                    {
                        Aes.KeySize = 192;
                    }
                    else
                    {
                        Aes.KeySize = 128;
                    }
                    Aes.GenerateKey();
                    Aes.GenerateIV();
                    key1 = Aes.Key;
                    iv1 = Aes.IV;
                    type1 = 1;
                }
                else if (i == 0 && typeselect == 2)
                {
                    tdes.GenerateKey();
                    tdes.GenerateIV();
                    key1 = tdes.Key;
                    iv1 = tdes.IV;
                    type1 = 2;
                }
                else if (i == 1 && typeselect == 1)
                {
                    keychoice = rnd.Next(1, 4);
                    if (keychoice == 3)
                    {
                        Aes.KeySize = 256;
                    }
                    else if (keychoice == 2)
                    {
                        Aes.KeySize = 192;
                    }
                    else
                    {
                        Aes.KeySize = 128;
                    }
                    Aes.GenerateKey();
                    Aes.GenerateIV();
                    key2 = Aes.Key;
                    iv2 = Aes.IV;
                    type2 = 1;
                }
                else if (i == 1 && typeselect == 2)
                {
                    tdes.GenerateKey();
                    tdes.GenerateIV();
                    key2 = tdes.Key;
                    iv2 = tdes.IV;
                    type2 = 2;
                }
            }

            encrypt1 = Encrypt(encrypt1, key1, iv1, type1, 0);
            byte[] embeddedbtyes = BitConverter.GetBytes(embeddedchar);
            size = encrypt1.Length;
            embedmarker = rnd.Next(1, size);
            endembed = (size / embedmarker);
            if ((size % embedmarker) != 0)
            {
                endembed++;
            }
            arr = new byte[size * 3];
            while (j < endembed)
            {
                for (i = 0; i < embedmarker; i++)
                {
                    if (arrayptr < encrypt1.Length)
                    {
                        arr[tracker] = encrypt1[arrayptr];
                        tracker++;
                        arrayptr++;
                    }
                    else
                    {
                        arr[tracker] = 0;
                        tracker++;
                    }
                }
                arr[tracker] = embeddedbtyes[0];
                tracker++;
                arr[tracker] = embeddedbtyes[1];
                tracker++;
                j++;
            }
            Array.Resize(ref arr, tracker);
            j = 0;
            tracker = 0;
            arrayptr = 0;
            while (j != endembed)
            {
                arrayptr = 0;
                byte[] pass = new byte[arr.Length / endembed];
                for (i = 0; i < (arr.Length / endembed); i++)
                {
                    pass[arrayptr] = arr[tracker];
                    tracker++;
                    arrayptr++;
                }
                pass = Encrypt(pass, key2, iv2, type2, 0);

                if (j == 0)
                {
                    if (temp.Length < pass.Length)
                    {
                        Array.Resize(ref temp, (pass.Length + temp.Length));
                        temp = pass;
                    }
                    else
                    {
                        temp = pass;
                    }
                }
                else
                {
                    byte[] temp1 = temp;
                    if (temp.Length < (pass.Length + temp.Length))
                    {
                        Array.Resize(ref temp, (pass.Length + temp1.Length));
                        System.Buffer.BlockCopy(temp1, 0, temp, 0, temp1.Length);
                        System.Buffer.BlockCopy(pass, 0, temp, temp1.Length, pass.Length);
                    }

                }

                j++;
            }
            byte[] store = temp;

            File.WriteAllBytes(OutputFile, store);
            if (type1 == 2)
            {
                Array.Resize(ref key1, key1.Length + 1);
            }
            if (type2 == 2)
            {
                Array.Resize(ref key2, key2.Length + 1);
            }
            int keylength1 = key1.Length;
            int keylength2 = key2.Length;
            byte keylength1b = Convert.ToByte(keylength1);
            byte keylength2b = Convert.ToByte(keylength2);
            byte[] keylength1arr = new byte[1];
            keylength1arr[0] = keylength1b;
            byte[] keylength2arr = new byte[1];
            keylength2arr[0] = keylength2b;
            byte[] EmbeddedInterval = BitConverter.GetBytes(embedmarker);
            byte[] TotalMarkers = BitConverter.GetBytes(endembed);
            byte[] OTEM_Key = new byte[keylength1arr.Length + keylength2arr.Length + key1.Length + key2.Length + iv1.Length + iv2.Length + embeddedbtyes.Length + EmbeddedInterval.Length + TotalMarkers.Length];
            System.Buffer.BlockCopy(keylength1arr, 0, OTEM_Key, 0, keylength1arr.Length);
            System.Buffer.BlockCopy(key1, 0, OTEM_Key, keylength1arr.Length, key1.Length);
            System.Buffer.BlockCopy(keylength2arr, 0, OTEM_Key, keylength1arr.Length + key1.Length, keylength2arr.Length);
            System.Buffer.BlockCopy(key2, 0, OTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length, key2.Length);
            System.Buffer.BlockCopy(iv1, 0, OTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length + key2.Length, iv1.Length);
            System.Buffer.BlockCopy(iv2, 0, OTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length + key2.Length + iv1.Length, iv2.Length);
            System.Buffer.BlockCopy(embeddedbtyes, 0, OTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length + key2.Length + iv1.Length + iv2.Length, embeddedbtyes.Length);
            System.Buffer.BlockCopy(EmbeddedInterval, 0, OTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length + key2.Length + iv1.Length + iv2.Length + embeddedbtyes.Length, EmbeddedInterval.Length);
            System.Buffer.BlockCopy(TotalMarkers, 0, OTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length + key2.Length + iv1.Length + iv2.Length + embeddedbtyes.Length + EmbeddedInterval.Length, TotalMarkers.Length);
            OTEMKey = OTEM_Key;

            #endregion

        }
        public void CTEM_KeyGen()
        {
            //declare crypto services
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            AesCryptoServiceProvider Aes = new AesCryptoServiceProvider();
            int i = 0, typeselect = 0, keychoice = 0;
            //create new random generator
            Random rnd = new Random();
            //create arrays for key1, key2, iv2
            byte[] key1 = new byte[0], key2 = new byte[0], iv2 = new byte[0];
            //loop for type selection and key gen
            for (i = 0; i < 2; i++)
            {
                //randomly select type as 1 or 3
                typeselect = rnd.Next(1, 3);
                //if 1 then Aes is selected
                if (i == 0 && typeselect == 1)
                {
                    //choose either 128, 196, or 256
                    keychoice = rnd.Next(1, 4);
                    if (keychoice == 3)
                    {
                        Aes.KeySize = 256;
                    }
                    else if (keychoice == 2)
                    {
                        Aes.KeySize = 192;
                    }
                    else
                    {
                        Aes.KeySize = 128;
                    }
                    //generate key and iv
                    Aes.GenerateKey();
                    Aes.GenerateIV();
                    //assign key value
                    Array.Resize(ref key1, Aes.Key.Length);
                    key1 = Aes.Key;
                }
                //if 2 then TDES
                else if (i == 0 && typeselect == 2)
                {
                    //generate Tdes key
                    tdes.GenerateKey();
                    tdes.GenerateIV();
                    //create key and store
                    Array.Resize(ref key1, tdes.Key.Length);
                    key1 = tdes.Key;
                    //add extra byte to be different from 196 bit AES
                    Array.Resize(ref key1, key1.Length + 1);
                }
                //if 1 then Aes is selected
                else if (i == 1 && typeselect == 1)
                {
                    //choose either 128, 196, or 256
                    keychoice = rnd.Next(1, 4);
                    if (keychoice == 3)
                    {
                        Aes.KeySize = 256;
                    }
                    else if (keychoice == 2)
                    {
                        Aes.KeySize = 192;
                    }
                    else
                    {
                        Aes.KeySize = 128;
                    }
                    //generate key and iv
                    Aes.GenerateKey();
                    Aes.GenerateIV();
                    //assign key and iv value
                    Array.Resize(ref key2, Aes.Key.Length);
                    Array.Resize(ref iv2, Aes.IV.Length);
                    key2 = Aes.Key;
                    iv2 = Aes.IV;
                }
                //if 2 then TDES
                else if (i == 1 && typeselect == 2)
                {
                    //generate Tdes key
                    tdes.GenerateKey();
                    tdes.GenerateIV();
                    //create key with iv and store
                    Array.Resize(ref key2, tdes.Key.Length);
                    Array.Resize(ref iv2, tdes.IV.Length);
                    key2 = tdes.Key;
                    iv2 = tdes.IV;
                    //add extra byte to be different from 196 bit AES
                    Array.Resize(ref key2, key2.Length + 1);
                }
            }
            //create key gen variables
            int keylength1 = key1.Length;
            int keylength2 = key2.Length;
            byte keylength1b = Convert.ToByte(keylength1);
            byte keylength2b = Convert.ToByte(keylength2);
            byte[] keylength1arr = new byte[1];
            keylength1arr[0] = keylength1b;
            byte[] keylength2arr = new byte[1];
            keylength2arr[0] = keylength2b;
            //create byte array for values to be copied into
            byte[] CTEM_Key = new byte[keylength1arr.Length + keylength2arr.Length + key1.Length + key2.Length + iv2.Length];
            //block copy all variables into byte in the order of Keylength1, Key1, Keylength2, Key2, iv2
            System.Buffer.BlockCopy(keylength1arr, 0, CTEM_Key, 0, keylength1arr.Length);
            System.Buffer.BlockCopy(key1, 0, CTEM_Key, keylength1arr.Length, key1.Length);
            System.Buffer.BlockCopy(keylength2arr, 0, CTEM_Key, keylength1arr.Length + key1.Length, keylength2arr.Length);
            System.Buffer.BlockCopy(key2, 0, CTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length, key2.Length);
            System.Buffer.BlockCopy(iv2, 0, CTEM_Key, keylength1arr.Length + key1.Length + keylength2arr.Length + key2.Length, iv2.Length);
            //assign final array to CTEMKey object type
            CTEMKey = CTEM_Key;
        }
        public void CTEM_Decrypt(string MessageLocation, string OutputFile)
        {
            //read file in as byte array
            byte[] decrypt1 = File.ReadAllBytes(MessageLocation);
            int type1 = 0, type2 = 0;
            byte[] iv1, iv2;
            //throw error if no key
            if(CTEMKey.Length == 0)
            {
                throw new System.ArgumentException("No Key", "CTEMKey");
            }
            //read key in
            byte[] keyin = CTEMKey;
            byte keylength = 0;
            //copy key in
            byte[] pull = keyin;
            //read first byte to find out size of key1
            Array.Resize(ref pull, 1);
            keylength = pull[0];
            //read in key1 
            byte[] key1 = new byte[keylength];
            System.Buffer.BlockCopy(keyin, 1, key1, 0, keylength);
            //override pull to read key2 length
            System.Buffer.BlockCopy(keyin, 1 + keylength, pull, 0, 1);
            keylength = pull[0];
            //read in key2 
            byte[] key2 = new byte[keylength];
            System.Buffer.BlockCopy(keyin, 2 + key1.Length, key2, 0, keylength);
            //if keylength is 25 then tdes, and iv1 is 8 bytes
            if (key1.Length == 25)
            {
                iv1 = new byte[8];
            }
            //otherwise AES then iv1 is 16 bytes
            else
            {
                iv1 = new byte[16];
            }
            //if keylength is 25 then tdes, and iv1 is 8 bytes
            if (key2.Length == 25)
            {
                //read in iv2
                iv2 = new byte[8];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length, iv2, 0, 8);
            }
            //otherwise AES then iv1 is 16 bytes
            else
            {
                iv2 = new byte[16];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length, iv2, 0, 16);
            }
            //if key2 is tdes chop off extra byte at end and assin type2 to 2
            if (key2.Length == 25)
            {
                type2 = 2;
                Array.Resize(ref key2, key2.Length - 1);
            }
            //otherwise AES and type2 is set to 1
            else
            {
                type2 = 1;
            }
            //if key1 is tdes chop off extra byte at end and assin type1 to 2
            if (key1.Length == 25)
            {
                type1 = 2;
                Array.Resize(ref key1, key1.Length - 1);
            }
            //otherwise AES and type1 is set to 1
            else
            {
                type1 = 1;
            }
            //decrypt first with key2 and iv2 
            decrypt1 = Decrypt(decrypt1, key2, iv2, type2, 0);
            //read iv1 off front of message
            System.Buffer.BlockCopy(decrypt1, 0, iv1, 0, iv1.Length);
            //decrypt again
            decrypt1 = Decrypt(decrypt1, key1, iv1, type1, 0);
            //copy decrypted message and leave out first iv1 length to get correct message
            byte[] decrypt2 = new byte[decrypt1.Length - iv1.Length];
            System.Buffer.BlockCopy(decrypt1, iv1.Length, decrypt2, 0, decrypt2.Length);
            //write to output file
            File.WriteAllBytes(OutputFile, decrypt2);
        }
        public void OTEM_Decrypt(string MessageLocation, string OutputFileLocation)
        {
            byte[] arr = File.ReadAllBytes(MessageLocation);
            byte[] firstdecrypt = new byte[0];
            byte[] iv1, iv2;
            int encrpytionsizemax;
            int x = 0;

            int type1 = 1, type2 = 1;
            if(OTEMKey.Length == 0)
            {
                throw new System.ArgumentException("No Key", "OTEMKey");
            }
            byte[] keyin = OTEMKey;
            byte keylength = 0;
            byte[] pull = keyin;
            Array.Resize(ref pull, 1);
            keylength = pull[0];
            byte[] key1 = new byte[keylength];
            System.Buffer.BlockCopy(keyin, 1, key1, 0, keylength);
            System.Buffer.BlockCopy(keyin, 1 + keylength, pull, 0, 1);
            keylength = pull[0];
            byte[] key2 = new byte[keylength];
            System.Buffer.BlockCopy(keyin, 2 + key1.Length, key2, 0, keylength);
            if (key1.Length == 25)
            {
                iv1 = new byte[8];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length, iv1, 0, 8);
            }
            else
            {
                iv1 = new byte[16];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length, iv1, 0, 16);
            }
            if (key2.Length == 25)
            {
                iv2 = new byte[8];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length + iv1.Length, iv2, 0, 8);
            }
            else
            {
                iv2 = new byte[16];
                System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length + iv1.Length, iv2, 0, 16);
            }
            Array.Resize(ref pull, 2);
            System.Buffer.BlockCopy(keyin, 2 + key1.Length + key2.Length + iv1.Length + iv2.Length, pull, 0, 2);
            char EmbeddedMarker = BitConverter.ToChar(pull, 0);
            Array.Resize(ref pull, 4);
            System.Buffer.BlockCopy(keyin, 4 + key1.Length + key2.Length + iv1.Length + iv2.Length, pull, 0, 4);
            int EmbeddedInterval = BitConverter.ToInt32(pull, 0);
            System.Buffer.BlockCopy(keyin, 8 + key1.Length + key2.Length + iv1.Length + iv2.Length, pull, 0, 4);
            int TotalMarkers = BitConverter.ToInt32(pull, 0);
            encrpytionsizemax = arr.Length / TotalMarkers;
            byte[] Embeddedbytes = BitConverter.GetBytes(EmbeddedMarker);

            if (key2.Length == 25)
            {
                type2 = 2;
                Array.Resize(ref key2, key2.Length - 1);
            }
            else
            {
                type2 = 1;
            }
            if (key1.Length == 25)
            {
                type1 = 2;
                Array.Resize(ref key1, key1.Length - 1);
            }
            else
            {
                type1 = 1;
            }
            int j = 0, i = 0, tracker = 0;

            while (j != TotalMarkers)
            {

                byte[] temp1 = new byte[encrpytionsizemax];
                x = 0;
                while (x < encrpytionsizemax && tracker < arr.Length)
                {
                    temp1[x] = arr[tracker];
                    tracker++;
                    x++;
                }
                    temp1 = Decrypt(temp1, key2, iv2, type2, 1);
                    byte[] search = temp1;
                    Array.Resize(ref search, search.Length + 1);
                    byte[] finalarr = new byte[EmbeddedInterval + 1];
                    if (search[EmbeddedInterval] == Embeddedbytes[0] && search[EmbeddedInterval + 1] == Embeddedbytes[1])
                    {
                        for (i = 0; i < EmbeddedInterval; i++)
                        {
                            finalarr[i] = search[i];
                        }
                        if (j == 0)
                        {
                            Array.Resize(ref finalarr, finalarr.Length - 1);
                            if (firstdecrypt.Length < finalarr.Length)
                            {
                                Array.Resize(ref firstdecrypt, (firstdecrypt.Length + finalarr.Length));
                                firstdecrypt = finalarr;
                            }
                            else
                            {
                                finalarr = firstdecrypt;
                            }
                        }
                        else if (j == TotalMarkers - 1)
                        {
                            int y = 0, e = 0;
                            bool end = false;
                            for (y = 0; y < finalarr.Length - 1; y++)
                            {
                                if (finalarr[y] == 0 && finalarr[y + 1] == 0 && end == false)
                                {
                                    e = y;
                                    end = true;
                                }
                            }
                            if (e == 0)
                            {
                                e = y;
                            }
                            byte[] hold = firstdecrypt;
                            Array.Resize(ref finalarr, e);
                            Array.Resize(ref firstdecrypt, (firstdecrypt.Length + finalarr.Length));
                            System.Buffer.BlockCopy(finalarr, 0, firstdecrypt, hold.Length, finalarr.Length);
                        }
                        else
                        {
                            Array.Resize(ref finalarr, finalarr.Length - 1);
                            int hold = firstdecrypt.Length;
                            Array.Resize(ref firstdecrypt, (firstdecrypt.Length + finalarr.Length));
                            System.Buffer.BlockCopy(finalarr, 0, firstdecrypt, hold, finalarr.Length);
                        }
                        j++;

                    }
                }
            firstdecrypt = Decrypt(firstdecrypt, key1, iv1, type1, 0);
            File.WriteAllBytes(OutputFileLocation, firstdecrypt);

        }
        private byte[] Encrypt(byte[] Data, byte[] key, byte[] IV, int Type, int mode)

        {
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            AesCryptoServiceProvider Aes = new AesCryptoServiceProvider();
            byte[] toEncryptArray = Data;
            //set the secret key for the tripleDES algorithm
            if (Type == 2)
            {
                tdes.Key = key;
                tdes.IV = IV;
                Aes.GenerateIV();
                Aes.GenerateKey();
            }
            //if the type is not 2 then use AES
            else
            {
                Aes.Key = key;
                Aes.IV = IV;
                tdes.GenerateIV();
                tdes.GenerateKey();
            }

            //mode of operation. there are other 4 modes. 
            //We choose CBC

            tdes.Mode = CipherMode.CBC;
            Aes.Mode = CipherMode.CBC;
            //padding mode(if any extra bytes need to be added)
            if (mode == 1)
            {
                tdes.Padding = PaddingMode.None;
                Aes.Padding = PaddingMode.None;
            }
            else
            {
                //This mode is awesome because it adds random data and not just zeros
                //causes a problem becuase it will pad when no padding needs to be done....(hence the if statement)
                //Probably why it was stopped being supported...
                //You can use any mode of padding, I just like this one because I view it as more secure
                tdes.Padding = PaddingMode.ISO10126;
                Aes.Padding = PaddingMode.ISO10126;
            }
            ICryptoTransform cTransform = tdes.CreateEncryptor(tdes.Key, tdes.IV);
            ICryptoTransform cTransformAes = Aes.CreateEncryptor(Aes.Key, Aes.IV);
            byte[] resultArray;
            if (Type == 2)
            {
                resultArray = cTransform.TransformFinalBlock(
                                     toEncryptArray, 0, toEncryptArray.Length);
            }
            else
            {
                resultArray = cTransformAes.TransformFinalBlock(
                                     toEncryptArray, 0, toEncryptArray.Length);
            }

            //Release resources held by TripleDes Encryptor                
            tdes.Clear();
            Aes.Clear();
            //return encrypted TEXT
            return resultArray;

        }
        private byte[] Decrypt(byte[] Data, byte[] key, byte[] IV, int Type, int mode)
        {
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            AesCryptoServiceProvider Aes = new AesCryptoServiceProvider();
            byte[] toEncryptArray = Data;
            //set the secret key for the tripleDES algorithm
            if (Type == 2)
            {
                tdes.Key = key;
                tdes.IV = IV;
                Aes.GenerateIV();
                Aes.GenerateKey();
            }
            else
            {
                Aes.Key = key;
                Aes.IV = IV;
                tdes.GenerateIV();
                tdes.GenerateKey();
            }

            //mode of operation. there are other 4 modes. 
            //We choose CBC

            tdes.Mode = CipherMode.CBC;
            Aes.Mode = CipherMode.CBC;
            //padding mode(if any extra byte added)
            if (mode == 1)
            {
                tdes.Padding = PaddingMode.None;
                Aes.Padding = PaddingMode.None;
            }
            else
            {
                tdes.Padding = PaddingMode.ISO10126;
                Aes.Padding = PaddingMode.ISO10126;
            }
            ICryptoTransform cTransform = tdes.CreateDecryptor(tdes.Key, tdes.IV);
            ICryptoTransform cTransformAes = Aes.CreateDecryptor(Aes.Key, Aes.IV);
            byte[] resultArray;
            if (Type == 2)
            {
                resultArray = cTransform.TransformFinalBlock(
                                     toEncryptArray, 0, toEncryptArray.Length);
            }
            else
            {
                resultArray = cTransformAes.TransformFinalBlock(
                                     toEncryptArray, 0, toEncryptArray.Length);
            }

            //Release resources held by TripleDes Encryptor                
            tdes.Clear();
            Aes.Clear();
            //return the Clear decrypted TEXT
            return resultArray;
        }

    }
    class Program : ToppsEncryptionMethod
    {
        private const string INPUT_FILE_NAME = "Encrypt.txt";
        private const string OUTPUT_FILE_NAME = "Encrypted.txt";
        private const string KEY_OUT = "Key.txt";
        private const string DECRYPTED_FILE = "Decrypted.txt";
        private const string CTEM_ENCRYPTED = "CTEM_Encrypted.txt";
        private const string CTEM_DECRYPTED = "CTEM_Decrypted.txt";
        private const string CTEM_KEY = "CTEM_Key.txt";

        static void Main(string[] args)
        {
            
            try
            {
                ToppsEncryptionMethod t = new ToppsEncryptionMethod();
                if (!File.Exists(INPUT_FILE_NAME))
                {
                    Console.WriteLine("{0} does not exist!", INPUT_FILE_NAME);
                    return;
                }
                FileStream fsIn = new FileStream(INPUT_FILE_NAME, FileMode.Open,
                    FileAccess.Read, FileShare.Read);
                // Create an instance of StreamReader that can read
                // characters from the FileStream.
                StreamReader sr = new StreamReader(fsIn);
                int count = 0;
                    string input = "init", pass = "init";
                    // While not at the end of the file, read lines from the file.
                    Console.WriteLine("Input: \n");
                    while (sr.Peek() > -1)
                    {
                        input = sr.ReadLine();
                        Console.WriteLine(input);
                        if (count == 0)
                        {
                            pass = input;
                        }
                        else
                        {
                            pass = pass + input;
                        }
                        count++;
                    }
                    sr.Close();
                    fsIn.Close();

                t.CTEM_KeyGen();
                File.WriteAllBytes(CTEM_KEY, t.CTEMKey);
                t.CTEMKey = File.ReadAllBytes(CTEM_KEY);
                t.CTEM_Encrypt(INPUT_FILE_NAME, CTEM_ENCRYPTED);
                t.CTEM_Decrypt(CTEM_ENCRYPTED,CTEM_DECRYPTED);
                t.OTEM_Encrypt(INPUT_FILE_NAME,OUTPUT_FILE_NAME);
                File.WriteAllBytes(KEY_OUT, t.OTEMKey);
                t.OTEM_Decrypt(OUTPUT_FILE_NAME,DECRYPTED_FILE);
                

            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("From: {0}.\nDetail: {1}", ex.Source, ex.Message);
            }
            finally
            {
                Console.WriteLine("\nPress any key to continue...");
                Console.ReadLine();
            }
        }
    }
}

