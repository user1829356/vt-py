import asyncio
import sys
import vt
import csv
from datetime import datetime

API_KEY = '' #your API key comes here

async def search_hash(client, hash_value):
    try:
        file_info = await client.get_object_async(f"/files/{hash_value}")
        return file_info, hash_value
    except Exception as e:
        return None, hash_value

async def search_url(client, url):
    try:
        url_info = await client.get_object_async(f"/urls/{vt.url_id(url)}")
        return url_info, url
    except Exception as e:
        return None, url

async def search_ip(client, ip):
    try:
        ip_info = await client.get_object_async(f"/ip_addresses/{ip}")
        return ip_info, ip
    except Exception as e:
        return None, ip

def display_info(entity_type, info, scanned_object):
    if info is None:
        return []

    result_info = [info.sha256, info.sha1, info.md5, info.last_analysis_date.strftime('%Y-%m-%d %H:%M:%S'), scanned_object]

    if entity_type == "-hash":
        last_analysis_results = info.last_analysis_results
        for vendor, result_data in last_analysis_results.items():
            result_info.append(result_data.get('result', 'Not available'))

    elif entity_type == "-url":
        last_analysis_results = info.last_analysis_results
        for vendor, result_data in last_analysis_results.items():
            result_info.append(result_data.get('result', 'Not available'))

    elif entity_type == "-ip":
        last_analysis_results = info.last_analysis_results
        for vendor, result_data in last_analysis_results.items():
            result_info.append(result_data.get('result', 'Not available'))

    return result_info

def main():
    loop = asyncio.get_event_loop()
    client = vt.Client(API_KEY)

    if len(sys.argv) != 3:
        print("Usage: python3 vt-py.py -[hash|url|ip] path/to/file.txt")
        sys.exit(1)

    option = sys.argv[1]
    filename = sys.argv[2]

    try:
        with open(filename, "r") as file:
            entities = [line.strip() for line in file.readlines()]
            if option == "-hash":
                results = loop.run_until_complete(asyncio.gather(*(search_hash(client, hash_value) for hash_value in entities)))
            elif option == "-url":
                results = loop.run_until_complete(asyncio.gather(*(search_url(client, url) for url in entities)))
            elif option == "-ip":
                results = loop.run_until_complete(asyncio.gather(*(search_ip(client, ip) for ip in entities)))
            else:
                print("Invalid option. Try again.")
                return

            now = datetime.now()
            timestamp_str = now.strftime("%Y%m%d_%H%M%S")
            with open(f"results_{timestamp_str}.csv", "w", newline='') as f:
                writer = csv.writer(f)
                if option == "-hash":
                    writer.writerow(['SHA-256', 'SHA-1', 'MD5', 'Date', 'Scanned Hash'] + [vendor for vendor in results[0][0].last_analysis_results.keys()])
                elif option == "-url":
                    writer.writerow(['URL', 'Date', 'Scanned URL'] + [vendor for vendor in results[0][0].last_analysis_results.keys()])
                elif option == "-ip":
                    writer.writerow(['IP', 'Scanned IP'] + [vendor for vendor in results[0][0].last_analysis_results.keys()])

                for result in results:
                    display = display_info(option, *result)
                    if display:
                        writer.writerow(display)

    except FileNotFoundError:
        pass
    finally:
        client.close()
        loop.close()

if __name__ == "__main__":
    main()
