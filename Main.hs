module Main where

import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString (send, recv)
import qualified Data.ByteString.Char8 as B8
import Data.Char (chr, ord)
import Data.Bits (xor)
import Numeric (readHex)
import Debug.Trace (trace, traceShowId, traceIO)

correctResponse = B8.pack "1\NUL"
incorrectResponse = B8.pack "0\NUL"

hexToBin [] = []
hexToBin (x:x2:xs) = (chr $ fst $ (readHex $ x:x2:[]) !! 0) : hexToBin xs

sendData host port handler = withSocketsDo $ do
  addrInfo <- getAddrInfo Nothing (Just host) (Just $ show port)
  let serverAddr = head addrInfo
  sock <- socket (addrFamily serverAddr) Stream defaultProtocol
  connect sock (addrAddress serverAddr)
  ret <- handler sock
  close sock
  return ret

encodeMessage blocks = ((chr $ length blocks):(concat blocks)) ++ [chr 0]

testData correct incorrect blocks sock = do
  send sock $ B8.pack $ encodeMessage blocks
  response <- recv sock 4096
  if response == correctResponse then correct
    else if response == incorrectResponse then incorrect
    else error "Faulty response from server"

replaceNth n newVal (x:xs)
  | n == 0 = newVal:xs
  | otherwise = x:replaceNth (n-1) newVal xs

performOnNth n func arr = replaceNth n (func $ arr !! n) arr

invertLsb n arr = performOnNth n (\x -> chr $ xor (ord x) 1) arr

findWorkingXorCharacter prepend (iv:blocks) index tester = test_ 0
  where
  test_ xorByte
    | xorByte == 256 = return Nothing
    | otherwise  = tester $ testData (verify xorByte) (test_ $ xorByte + 1) (prepend ++ ((xoredIv index xorByte):blocks))
  verify xorByte = if index /= (length iv) - 1 then return $ Just xorByte
                                               else verify_ xorByte
  verify_ xorByte = tester $ testData (return $ Just xorByte) (test_ $ xorByte + 1) (prepend ++ ((invertLsb (index - 1) $ xoredIv index xorByte):blocks))
  xoredIv index value = performOnNth index (\x -> chr $ xor value $ ord x) iv

findValueForIndexInLastBlock prepend encrypted@(iv:blocks) index tester = do
  xorForPadding <- findWorkingXorCharacter prepend encrypted index tester
  traceIO $ "Working value: " ++ show xorForPadding
  let paddingValue = (length iv) - index
  traceIO $ "Padding value: " ++ show paddingValue
  traceIO $ "IV value: " ++ (show $ ord $ iv !! index)
  case xorForPadding of Just xored -> return $ Just $ xor xored paddingValue
                        Nothing    -> return Nothing

splitIntoBlocks _ [] = []
splitIntoBlocks blockSize input = firstBlock:splitIntoBlocks blockSize rest
  where
  (firstBlock, rest) = splitAt blockSize input

setLastPaddingAccordingToValue iv found = plain ++ mixed
  where
    fromIv = length iv - length found
    (plain, toXor) = splitAt fromIv iv
    padding = length found + 1
    mixed = zipWith (\x y -> chr $ xor padding $ xor (ord x) y) toXor found

findPlaintext encrypted@(iv:rest) sock = findLastValue [] encrypted [] []
  where
    findLastValue finished (iv:toHack) hacked known
      | length toHack == 0 = return $ concat hacked
      | length known == length iv = findLastValue (finished ++ [iv]) toHack (hacked ++ [map chr known]) []
      | otherwise = do
        let newIv = setLastPaddingAccordingToValue iv known
        value_ <- findValueForIndexInLastBlock finished [newIv, head toHack] (length iv - length known - 1) (\x -> x sock)
        let Just value = value_
        findLastValue finished (iv:toHack) hacked (value:known)

main :: IO ()
main = do
  putStrLn "This program will hack a CBC-mode PKCS #5 encrypted text with a blocksize of 16 bytes. It needs a server that takes 'blocks_count(1) | blocks(16 * blocks_count) | null(1)' and responds \"0\\n\" on failure and \"1\\n\" on success."
  putStrLn "Input data to be decrypted"
  fileData_ <- getLine
  let fileData = hexToBin fileData_
  let encrypted = splitIntoBlocks 16 fileData
  putStrLn "Input IP to connect to"
  ip <- getLine
  putStrLn "Input port to connect to"
  port_ <- getLine
  let port = read port_ :: Int
  putStrLn "Starting test"
  sendData ip port $ (\x -> do y <- findPlaintext encrypted x
                               let (msg,padding) = splitAt ((length y) - (ord $ last y)) y
                               if padding /= (replicate (length padding) (chr $ length padding)) then putStrLn $ show y
                                                                                                 else putStrLn msg)
  putStrLn "Done"
