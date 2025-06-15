from web3 import Web3
from eth_utils import to_hex
from eth_account import Account
from eth_account.messages import encode_defunct
from aiohttp import ClientSession, ClientTimeout, ClientResponseError
import asyncio, secrets, os, random

class PharosTestnet:
    def __init__(self) -> None:
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": "https://testnet.pharosnetwork.xyz",
            "Referer": "https://testnet.pharosnetwork.xyz/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        self.BASE_API = "https://api.pharosnetwork.xyz"
        self.RPC_URL = "https://testnet.dplabs-internal.com"
        self.ref_code = "PNFXEcz1CWezuu3g"

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(message)

    def welcome(self):
        print("\nPharos Testnet Transfer Bot")
        print("--------------------------\n")

    def generate_address(self, account: str):
        try:
            account = Account.from_key(account)
            return account.address
        except Exception:
            return None

    def generate_random_receiver(self):
        try:
            private_key_bytes = secrets.token_bytes(32)
            private_key_hex = to_hex(private_key_bytes)
            account = Account.from_key(private_key_hex)
            return account.address
        except Exception:
            return None

    def generate_url_login(self, account: str, address: str):
        try:
            encoded_message = encode_defunct(text="pharos")
            signed_message = Account.sign_message(encoded_message, private_key=account)
            signature = to_hex(signed_message.signature)
            return f"{self.BASE_API}/user/login?address={address}&signature={signature}&invite_code={self.ref_code}"
        except Exception:
            return None

    async def get_web3_with_check(self, retries=3, timeout=60):
        for i in range(retries):
            try:
                web3 = Web3(Web3.HTTPProvider(self.RPC_URL, request_kwargs={"timeout": timeout}))
                web3.eth.get_block_number()
                return web3
            except Exception:
                await asyncio.sleep(3)
        raise Exception("Failed to connect to RPC")

    async def get_token_balance(self, address: str):
        try:
            web3 = await self.get_web3_with_check()
            balance = web3.eth.get_balance(address)
            return balance / (10 ** 18)
        except Exception as e:
            self.log(f"Error getting balance: {str(e)}")
            return None

    async def perform_transfer(self, account: str, address: str, receiver: str, amount: float):
        try:
            web3 = await self.get_web3_with_check()
            tx = {
                "to": receiver,
                "value": web3.to_wei(amount, "ether"),
                "nonce": web3.eth.get_transaction_count(address, 'pending'),
                "gas": 21000,
                "gasPrice": web3.eth.gas_price,
                "chainId": web3.eth.chain_id
            }
            signed_tx = web3.eth.account.sign_transaction(tx, account)
            raw_tx = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            tx_hash = web3.to_hex(raw_tx)
            receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            return tx_hash, receipt.blockNumber
        except Exception as e:
            self.log(f"Transfer failed: {str(e)}")
            return None, None

    def mask_account(self, account):
        try:
            return account[:6] + '...' + account[-4:]
        except Exception:
            return None

    async def print_timer(self, seconds: int):
        for remaining in range(seconds, 0, -1):
            print(f"Waiting {remaining} seconds...", end='\r')
            await asyncio.sleep(1)
        print(' ' * 50, end='\r')

    async def user_login(self, url_login: str, retries=5):
        headers = {**self.headers, "Authorization": "Bearer null", "Content-Length": "0"}
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.post(url=url_login, headers=headers) as response:
                        response.raise_for_status()
                        result = await response.json()
                        return result["data"]["jwt"]
            except (Exception, ClientResponseError):
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                return None

    async def get_user_points(self, address: str, token: str, retries=5):
        url = f"{self.BASE_API}/user/profile?address={address}"
        headers = {**self.headers, "Authorization": f"Bearer {token}"}
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.get(url=url, headers=headers) as response:
                        response.raise_for_status()
                        result = await response.json()
                        if "code" in result and result["code"] != 0:
                            await asyncio.sleep(5)
                            continue
                        return result.get("data", {}).get("user_info", {}).get("TotalPoints", 0)
            except (Exception, ClientResponseError):
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                return None

    async def sign_in(self, address: str, token: str, retries=5):
        url = f"{self.BASE_API}/sign/in?address={address}"
        headers = {**self.headers, "Authorization": f"Bearer {token}", "Content-Length": "0"}
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.post(url=url, headers=headers) as response:
                        response.raise_for_status()
                        result = await response.json()
                        if "code" in result and result["code"] not in [0, 1]:
                            await asyncio.sleep(5)
                            continue
                        return result
            except (Exception, ClientResponseError):
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                return None

    async def verify_transfer(self, address: str, token: str, tx_hash: str, retries=5):
        url = f"{self.BASE_API}/task/verify?address={address}&task_id=103&tx_hash={tx_hash}"
        headers = {**self.headers, "Authorization": f"Bearer {token}", "Content-Length": "0"}
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.post(url=url, headers=headers) as response:
                        response.raise_for_status()
                        result = await response.json()
                        if "code" in result and result["code"] != 0:
                            await asyncio.sleep(5)
                            continue
                        return result
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(f"Verification error: {str(e)}")
                return None

    async def process_account(self, account: str, tx_count: int):
        address = self.generate_address(account)
        if not address:
            self.log("Invalid account private key")
            return

        self.log(f"Processing account: {self.mask_account(address)}")

        url_login = self.generate_url_login(account, address)
        if not url_login:
            self.log("Failed to generate login URL")
            return

        token = await self.user_login(url_login)
        if not token:
            self.log("Login failed")
            return

        current_points = await self.get_user_points(address, token) or 0
        self.log(f"Current points: {current_points}")

        sign_in = await self.sign_in(address, token)
        if sign_in and sign_in.get("msg") == "ok":
            self.log("Daily check-in successful")
        elif sign_in and sign_in.get("msg") == "already signed in today":
            self.log("Already checked in today")
        else:
            self.log("Check-in failed")

        for i in range(1, tx_count + 1):
            self.log(f"\nPreparing transfer {i}/{tx_count}")

            receiver = self.generate_random_receiver()
            balance = await self.get_token_balance(address)

            if balance is None:
                self.log("Failed to check balance")
                break

            # Generate random amount between 0.000001 and 0.000009
            tx_amount = round(random.uniform(0.000001, 0.000009), 6)
            if balance <= tx_amount:
                self.log(f"Insufficient balance: {balance:.6f} PHRS")
                break

            self.log(f"Sending {tx_amount:.6f} PHRS to {receiver}")

            tx_hash, block_number = await self.perform_transfer(account, address, receiver, tx_amount)
            if not tx_hash:
                continue

            self.log(f"Transaction sent: {tx_hash}")

            verify = await self.verify_transfer(address, token, tx_hash)
            if verify and verify.get("msg") == "task verified successfully":
                new_points = await self.get_user_points(address, token) or current_points
                points_earned = new_points - current_points
                current_points = new_points
                self.log(f"+{points_earned} points | Total: {current_points}")
            else:
                self.log("Verification failed")

            if i < tx_count:
                await self.print_timer(random.randint(5, 10))

    async def main(self):
        try:
            if not os.path.exists('pk.txt'):
                print("Error: accounts.txt file not found")
                return

            with open('pk.txt', 'r') as file:
                accounts = [line.strip() for line in file if line.strip()]

            if not accounts:
                print("No accounts found in pk.txt")
                return

            print("\nPharos Testnet Transfer Bot")
            print("--------------------------")

            while True:
                try:
                    tx_count = int(input("Enter number of transfers per account: "))
                    if tx_count > 0:
                        break
                    print("Please enter a positive number")
                except ValueError:
                    print("Invalid input, please enter a number")

            self.clear_terminal()
            self.welcome()
            self.log(f"Loaded {len(accounts)} accounts")
            self.log(f"Will perform {tx_count} transfers of random amounts (0.000001-0.000009 PHRS)\n")

            for account in accounts:
                await self.process_account(account, tx_count)
                self.log("\n" + "="*50 + "\n")

            self.log("All transfers completed")

        except Exception as e:
            self.log(f"Error: {str(e)}")

if __name__ == "__main__":
    try:
        bot = PharosTestnet()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print("\nTransfer bot stopped by user")
