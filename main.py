import Constants
from Cryptanalyse import Cryptanalyse


def main():
    cryptanalyse = Cryptanalyse(cipher_text=Constants.CAESER_CIPHER_TEXT)
    caeser_cipher_result = cryptanalyse.analyse_correlation_frequency()

    print "\n1. Caeser Cipher Result (Correlation Frequency Analysis)"
    print "--------------------------------------------------------\n"

    print "KEY\tPLAIN TEXT"
    print "===\t=========="
    for key, plain_text in caeser_cipher_result.iteritems():
        print str(key) + " \t" + plain_text

    print "\nKey: 5"
    print "Plain Message: GO CYBEREAGLES"

    print "\n2. Vignere Cipher Result (Index of Coincidence Analysis)"
    print "----------------------------------------------------------\n"

    cryptanalyse.analyse_vignere_cipher(Constants.VIGNERE_CIPHER_TEXT)
    print "\n"
















if __name__ == "__main__":
    main()










