import os
import hashlib
import time
from prettytable import PrettyTable
from virustotal_python import Virustotal


Malicious_Hashes = {
  "something",
  "something", }


API_Key = "add key here"


def calculate_hash(file_path, algorithm="sha256"):
#calculate the hash file



  try:
      hash_func = hashlib.new(algorithm)
      with open(file_path, 'rb') as f:
          while chunk := f.read(8192):
              hash_func.update(chunk)
      return hash_func.hexdigest()
  except FileNotFoundError:
      print(f"File not found: {file_path}")
      return None
  except Exception as e:
      print(f"Error calculating hash of {file_path}: {e}")
      return None




def check_file(file_path):
  # checking if its malicious of clean
  file_hash = calculate_hash(file_path)
  if not file_hash:
      return None
    

  # VirusTotal 
  try:
      vtotal = Virustotal(API_KEY=API_Key)
      response = vtotal.file_report([file_hash])
      if response and response["data"]:
          result = "Malicious" if response["data"][0]["attributes"]["last_analysis_stats"][
                                      "malicious"] > 0 else "Clean"
      else:
          result = "Unknown"
  except Exception as e:
      print(f"Error checking VirusTotal: {e}")
      # local hash list
      result = "Malicious" if file_hash in Malicious_Hashes else "Clean"


  return file_path, file_hash, result


def scan_directory(directory):
  #Checking all files in directory
  results = []
  for root, _, files in os.walk(directory):
      for file in files:
          file_path = os.path.join(root, file)
          result = check_file(file_path)
          if result:
              results.append(result)
  return results


def display_results(results):
  # Display in a table
  table = PrettyTable()
  table.field_names = ["File Path", "Hash", "Status"]
  table.align = "l"  # Left-align
  table.border = True
  table.padding_width = 1


  for file_path, file_hash, status in results:
      if status == "Malicious":
          table.add_row([file_path, file_hash, f"\033[91m{status}\033[0m"])  # Red for malicious
      elif status == "Clean":
          table.add_row([file_path, file_hash, f"\033[92m{status}\033[0m"])  # Green for clean
      else:
          table.add_row([file_path, file_hash, status])


  print(table)

#Implementation

def main():
  print("\n--- DS Integrity Scanner ---\n")
  # Display initial options in a table
  options_table = PrettyTable()
  options_table.field_names = ["Option", "Description"]
  options_table.add_row(["1", "Check one file"])
  options_table.add_row(["2", "Scan a directory"])
  print(options_table)

  choice = input("Which would you like to check? (1 or 2): ").strip()

  start_time = time.time()

  if choice == "1":
      file_path = input("File path: ").strip()
      result = check_file(file_path)
      if result:
          table = PrettyTable()
          table.field_names = ["File Path", "Hash", "Status"]
          table.add_row(result)
          print("\n--- Scan Result ---")
          print(table)
      else:
          print("No result returned. File may not exist or an error occurred.")
  elif choice == "2":
      directory = input("Directory path: ").strip()
      results = scan_directory(directory)
      if results:
          print("\n--- Scan Results ---")
          display_results(results)
      else:
          print("No results. Directory may be empty or an error occurred.")
  else:
      print("ERROR: Invalid choice.")

  end_time = time.time()
  print(f"\nCompleted in {end_time - start_time:.2f} seconds.")



if __name__ == "__main__":
  main()






