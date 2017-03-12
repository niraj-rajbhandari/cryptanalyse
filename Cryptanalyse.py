import Constants
import itertools


class Cryptanalyse:
    """
    Class to cryptanalyse Caeser and Vignere Cipher
    @author Niraj Rajbhandari
    """

    def __init__(self, cipher_text):
        self.xx_chart = {}
        self.cipher_text = cipher_text
        self.generate_xx_chart()

    def generate_xx_chart(self):
        """
        Generates the XX chart
        :return:
        """
        for index, letter in enumerate(Constants.LETTERS):
            self.xx_chart[letter] = {
                "index": index,
                "frequency": Constants.FREQUENCIES[index]
            }

    def calculate_correlation_frequency(self, letter_frequencies, limit=5):
        """
        Calculates the correlation frequencies for cipher text
        :param letter_frequencies: frequencies of each letter in the cipher text
        :param limit: number of top frequencies to evaluate
        :return: returns top limit correlation frequencies and the corresponding key
        """
        correlation_frequencies = {}
        for i in range(0, len(Constants.LETTERS)):
            correlation_frequencies[i] = 0
            for letter, frequency in letter_frequencies.iteritems():
                letter_freq_probability = frequency / float(len(letter_frequencies))
                xx_chart_letter_index = self.caeser_decipher(self.xx_chart[letter]["index"], i)
                xx_chart_letter_freq_probability = self.xx_chart[Constants.LETTERS[xx_chart_letter_index]]["frequency"]
                correlation_frequencies[i] += letter_freq_probability * xx_chart_letter_freq_probability
        return sorted(correlation_frequencies, key=correlation_frequencies.get, reverse=True)[:limit]

    def analyse_correlation_frequency(self, cipher_text=None, limit=5):
        """
        Analyses the cipher text correlation frequency
        :param cipher_text: cipher text to be analysed
        :param limit: limit of top frequencies to be considered
        :return: map with key and plain text associated with the key
        """
        cipher_text = self.cipher_text if cipher_text is None else cipher_text
        letter_frequencies = self.calculate_letter_frequencies(cipher_text)
        correlation_frequencies_key = self.calculate_correlation_frequency(letter_frequencies, limit)
        analysis_result = {}
        for key in correlation_frequencies_key:
            analysis_result[key] = ""
            for cipher_letter in cipher_text:
                plain_key = self.caeser_decipher(self.xx_chart[cipher_letter]["index"], key) if cipher_letter != " " else " "
                analysis_result[key] += Constants.LETTERS[plain_key] if cipher_letter != " " else " "

        return analysis_result

    def analyse_vignere_cipher(self,cipher_text=None):
        """
        Vignere Cipher cryptanalysis (Displays the results)
        :param cipher_text: cipher text to be decrypted
        :return:
        """
        cipher_text = self.cipher_text if cipher_text is None else cipher_text
        index_of_coincidence = self.calculate_index_of_coincidence(cipher_text)

        print "Index of Coincidence: "+ str(index_of_coincidence)
        key_period = self.get_key_period(index_of_coincidence)
        print "Key period: "+str(key_period)
        bucket = self.bucketize_cipher_text(key_period,cipher_text)

        self.display_examined_frequency_pattern(bucket)
        print "\nTried Frequency Examination on each bucket. Results were not conclusive"

        print "\nCalculated probable keys for each bucket using correlation frequency. Selected the key with highest Correlation Frequency"
        probable_keys_per_bucket = self.get_probable_keys_per_bucket(bucket)
        self.display_probable_keys(probable_keys_per_bucket)

        probable_keys = itertools.product(probable_keys_per_bucket[0], probable_keys_per_bucket[1]
                                          ,probable_keys_per_bucket[2], probable_keys_per_bucket[3],
                                          probable_keys_per_bucket[4], probable_keys_per_bucket[5])

        print "\nThe deciphered message is:"
        print "=========================="
        for probable_key_combination in probable_keys:
            self.get_vignere_deciphered_text(cipher_text, probable_key_combination)


    def caeser_encipher(self, plain_letter_index, key):
        """
        Encipher using Caeser cipher
        :param plain_letter_index: index of plain letter to be enciphered
        :param key: key to be used to enciphered
        :return: enciphered letter
        """
        return (plain_letter_index + key) % 26

    def caeser_decipher(self, cipher_letter_index, key):
        """
        Decipher using Caeser cipher
        :param plain_letter_index: index of plain letter to be deciphered
        :param key: key to be used to deciphered
        :return: deciphered letter
        """
        return (26 + cipher_letter_index - key) % 26

    def calculate_letter_frequencies(self, cipher_text):
        """
        Calculate frequencies of letter in a string
        :param cipher_text: string whose letter frequency is to be calculated
        :return: frequency of letters in a string
        """
        cipher_letter_frequency = {}
        for letter in cipher_text:
            if letter != " ":
                cipher_letter_frequency[letter.upper()] = cipher_letter_frequency[letter.upper()]+1 if letter.upper() in cipher_letter_frequency else 1

        return cipher_letter_frequency

    def calculate_index_of_coincidence(self,cipher_text=None):
        """
        Calculate index of coincidence for a cipher text
        :param cipher_text: cipher text
        :return: IC of the cipher text
        """
        cipher_text = self.cipher_text if cipher_text is None else cipher_text
        cipher_letter_frequency = self.calculate_letter_frequencies(cipher_text)
        cipher_text_length = len(cipher_text.replace(" ",""))
        sum_of_frequencies = 0
        for letter, frequency in cipher_letter_frequency.iteritems():
            sum_of_frequencies += (frequency * (frequency-1))

        return sum_of_frequencies/float(cipher_text_length*(cipher_text_length-1))

    def get_key_period(self,index_of_coincidence):
        """
        Gets probable key period from index of coincidence
        :param index_of_coincidence: IC of cipher text
        :return: probable period of key
        """
        key_period = 1
        if 0.052 <= index_of_coincidence < 0.066:
            actual_ic = self.get_closer_value(0.052, 0.066, index_of_coincidence)
            key_period = 1 if actual_ic == 0.066 else 2
        elif 0.047 <= index_of_coincidence < 0.052:
            actual_ic = self.get_closer_value(0.047, 0.052, index_of_coincidence)
            key_period = 2 if actual_ic == 0.052 else 3
        elif 0.045 <= index_of_coincidence < 0.047:
            actual_ic = self.get_closer_value(0.045, 0.047, index_of_coincidence)
            key_period = 3 if actual_ic == 0.047 else 4
        elif index_of_coincidence == 0.044:
            key_period = 5
        elif 0.0425 <= index_of_coincidence < 0.044:
            actual_ic = self.get_closer_value(0.0425, 0.044, index_of_coincidence)
            key_period = 5 if actual_ic == 0.044 else 6
        elif 0.041 <= index_of_coincidence < 0.0425:
            actual_ic = self.get_closer_value(0.041,0.044,index_of_coincidence)
            key_period = 6 if actual_ic == 0.0425 else 10
        elif index_of_coincidence < 0.041:
            raise RuntimeError("very big key period with index of coincidence: " + str(index_of_coincidence))

        return key_period

    def get_closer_value(self, min_value, max_value, value):
        """
        Gets the value closer to given value in a range
        :param min_value: min of the range
        :param max_value: max of the range
        :param value: value to be checked
        :return: min or max closer to the value
        """
        return max_value if abs(max_value - value) < abs(min_value - value) else min_value

    def bucketize_cipher_text(self, key_period, cipher_text):
        """
        Bucketize the cipher texts into different buckets
        :param key_period: period of the key
        :param cipher_text: cipher text
        :return:buckets with distributed cipher text
        """
        bucket = {}
        cipher_text_index = 0
        cipher_text = cipher_text.replace(" ","")
        while cipher_text_index < len(cipher_text):
            if cipher_text[cipher_text_index] != " ":
                bucket_index = (cipher_text_index % key_period)
                bucket[bucket_index] = bucket[bucket_index] if bucket_index in bucket else ""
                bucket[bucket_index] += cipher_text[cipher_text_index]
            cipher_text_index += 1

        return bucket

    def get_probable_keys_per_bucket(self, bucket):
        """
        Get Probable keys for each bucket
        :param bucket: buckets with cipher text
        :return: probable keys
        """
        probable_keys = {}
        for bucket_index, bucketized_cipher_text in bucket.iteritems():
            letter_frequencies = self.calculate_letter_frequencies(bucketized_cipher_text)
            correlation_frequencies_key = self.calculate_correlation_frequency(letter_frequencies, limit=1)
            probable_keys[bucket_index] = correlation_frequencies_key

        return probable_keys

    def get_vignere_deciphered_text(self, cipher_text, key_list):
        """
        Gets Vignere deciphered plain text
        :param cipher_text:  cipher text
        :param key_list: list of keys to be used for each bucket
        :return: plain text
        """
        cipher_text_index = 0
        plain_text = ""
        for letter in cipher_text:
            if letter == " ":
                plain_text += " "
            else:
                plain_text += Constants.LETTERS[self.caeser_decipher(self.xx_chart[letter]["index"],key_list[cipher_text_index % len(key_list)])]
                cipher_text_index += 1
        print "\tWithout Whitespace:"
        print "\t-------------------"
        print "\t" + plain_text.replace(" ","") + "\n"

        print "\tWith Whitespace:"
        print "\t-------------------"
        print "\t" + plain_text

    def examine_bucket_frequency(self, buckets):
        """
        Examines Frequency for each bucket
        :param buckets: buckets with cipher text
        :return: examined frequency results
        """
        letter_frequency = {}
        for letter in Constants.LETTERS:
            letter_frequency[letter] = 0

        bucket_frequency = {}

        for bucket_index, bucket_cipher_text in buckets.iteritems():
            bucket_freq = self.calculate_letter_frequencies(bucket_cipher_text)
            bucket_frequency[bucket_index] = dict(letter_frequency.items() + bucket_freq.items())

        return bucket_frequency

    def display_examined_frequency_pattern(self,bucket):
        """
        Displays examined frequency results
        :param bucket: bucket with cipher text
        :return:
        """
        bucket_frequencies = self.examine_bucket_frequency(bucket)
        header = "             "
        border = "============="
        for index, letter in enumerate(Constants.LETTERS):
            header += "  "+str(letter)
            border += "==="
        print "\nFREQUENCY EXAMINATION\n"
        print header

        print border

        for bucket_index,bucket_frequency in bucket_frequencies.iteritems():
            row_item = "bucket: "+str(bucket_index)+"|   "
            for letter in Constants.LETTERS:
                row_item += "  " + str(bucket_frequency[letter])
            print row_item

    def display_probable_keys(self,probable_keys):
        """
        Displays probable keys for each bucket
        :param probable_keys: probable keys for each bucket
        :return:
        """
        print "Keys Selected Per Bucket"
        print "========================"
        for bucket_index,keys in probable_keys.iteritems():
            row_item = "\tBucket "+str(bucket_index)+": "
            for index,key in enumerate(keys):
                row_item += str(key) if len(keys)-1 == index else str(key) + ","

            print row_item





