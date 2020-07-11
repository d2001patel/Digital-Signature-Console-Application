using System;
using static System.Console;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using MySql.Data.MySqlClient;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using BcX509 = Org.BouncyCastle.X509;
using DotNetUtils = Org.BouncyCastle.Security.DotNetUtilities;

namespace ConsoleApp1
{
    class Program
    {
        //Credentials for the Database Connection
        static string serverIp = "Valid SeverIp";
        static string username = "Valid Username";
        static string password = "Valid Password";
        static string databaseName = "Valid Database";
         public static int PSNumber(string pathstring)
        {
            //Function returns all the PSN Numbers in an int Array
            string pdfname = Path.GetFileName(pathstring);
            var name = pdfname.Split('.');
            var number = name[0].Split('_');
            int psn = Int32.Parse(number[1]);
            return psn;
        }
        public static string[] details(int[] psn)
        {
            //Function prints the SQL Details and returns an Array of the fetched Subject key Identifiers from the Database
            string[] ski = new string[50];
            for (int i = 0; psn[i] != 0; i++)
            {
                
                Console.WriteLine(psn[i]);
                string dbConnectionString = string.Format("server={0};uid={1};pwd={2};database={3};", serverIp, username, password, databaseName);
                var conn = new MySql.Data.MySqlClient.MySqlConnection(dbConnectionString);
                MySqlCommand command = conn.CreateCommand();
                command.CommandText = "SELECT * FROM signaturedb.signature WHERE psn_number=('" + psn[i] + "')";
                try
                {
                    conn.Open();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                MySqlDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    ski[i] = reader["key"].ToString();
                    Console.WriteLine(reader["key"].ToString());
                    Console.WriteLine(reader["password"].ToString());
                    Console.WriteLine(reader["key_text"].ToString());
                }
            }
            return ski;
        }
        
        static void Main(string[] args)
        {
            //All pdf files are fetched from a particular folder
            string[] pdfFiles = Directory.GetFiles("PATH1", "*.pdf")
                                     .Select(Path.GetFileName)
                                     .ToArray();
            string[] pdfpaths = Directory.GetFiles("PATH1", "*.pdf").ToArray();
            string[] newfilepaths = new string[50];
            int[] psn = new int[50];
            string[] ski;

            for (int i = 0; i < pdfFiles.Length; i++)
            {
                psn[i] = PSNumber(pdfFiles[i]);
                string[] address = {@"PATH2",pdfFiles[i]};
                newfilepaths[i] = Path.Combine(address);
            }

            ski = details(psn);
            
            for (int i = 0; psn[i] != 0; i++)
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindBySubjectKeyIdentifier, ski[i], true);
                X509Certificate2 digitalID = fcollection[0];
                PdfReader reader = new PdfReader(pdfpaths[i]);
                PdfStamper stamper = PdfStamper.CreateSignature(reader,
                new FileStream(newfilepaths[i], FileMode.Create), '\0');
                PdfSignatureAppearance sap = stamper.SignatureAppearance;
                sap.SetVisibleSignature(new iTextSharp.text.Rectangle(100, 100, 250, 150), 1, null);
                BcX509.X509Certificate bcCert = DotNetUtils.FromX509Certificate(digitalID);
                var chain = new List<BcX509.X509Certificate> { bcCert };
                var privatekey = Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(digitalID.PrivateKey).Private;
                IExternalSignature es = new PrivateKeySignature(privatekey, "SHA-256");
                MakeSignature.SignDetached(sap, es, chain,
                null, null, null, 0, CryptoStandard.CMS);
                stamper.Close();
                store.Close();
            }
        }
    }
}