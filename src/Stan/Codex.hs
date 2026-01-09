{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE NumericUnderscores #-}

module Stan.Codex
    ( runCodex
    ) where

import Colourista (bold, cyan, errorMessage, infoMessage, successMessage, warningMessage, formatWith)
import Data.Aeson (FromJSON, ToJSON, parseJSON, withObject, (.:))
import qualified Data.Aeson as Aeson
import qualified Data.Text as T

import Control.Exception (try)
import Control.Concurrent (threadDelay)
import System.Directory.Recursive (getDirRecursive)
import Network.HTTP.Simple (httpLBS, getResponseBody, getResponseStatusCode, setRequestBodyJSON, setRequestHeaders, parseRequest, HttpException)

import Data.List (isSuffixOf)

-- | Run the Codex AI scanner.
runCodex :: IO ()
runCodex = do
    putStrLn $ formatWith [bold, cyan] "Starting AI-Powered Vulnerability Scanner (Integrated Stan Module)..."
    
    maybeKey <- lookupEnv "GEMINI_API_KEY"
    case maybeKey of
        Just key -> do
            successMessage "Gemini API Key detected. Using Google Gemini..."
            runScan key
        Nothing -> do
            warningMessage "GEMINI_API_KEY not found."
            infoMessage "Please export GEMINI_API_KEY (get one for free at aistudio.google.com)."
            putStrLn "Skipping AI analysis."

runScan :: String -> IO ()
runScan key = do
    files <- getPlutusFiles "src"
    infoMessage $ "Found " <> show (length files) <> " source files."

    -- STRICT SEQUENTIAL EXECUTION
    -- Gemini Free Tier allows ~15 Requests Per Minute (1 req every 4 seconds).
    -- We must respect this to avoid 429 errors.
    mapM_ (processFile key) files

-- | Core orchestration logic for a single file
processFile :: String -> FilePath -> IO ()
processFile key file = do
    content <- readFileText file
    when (isPlinthFile content) $ do
         putTextLn $ "  " <> formatWith [bold] ("[ANALYZING] " <> toText file <> "...")
         -- Enforce Rate Limit: Wait 4 seconds (15 RPM)
         threadDelay 4_000_000 
         
         -- Retry logic handles occasional hiccups
         result <- retryWithBackoff 5 (callGemini key content)
         case result of
             Right (Just analysis) -> do
                 warningMessage ("  -> Report for " <> toText file <> ":")
                 putStrLn analysis
             Right Nothing -> pass -- No vulnerability found or empty response
             Left err -> handleError file err

-- | Retry an action with exponential backoff if it returns ApiError 429
retryWithBackoff :: Int -> IO (Either CodexError a) -> IO (Either CodexError a)
retryWithBackoff 0 action = action
retryWithBackoff retries action = do
    result <- action
    case result of
        Left (ApiError 429) -> do
            -- Wait 10s, 20s... aggressive backoff if we still hit it
            let delay = (6 - retries) * 10
            warningMessage $ "  Rate limit hit. Retrying in " <> show delay <> " seconds..."
            threadDelay (delay * 1_000_000)
            retryWithBackoff (retries - 1) action
        _ -> return result

-- | Pure logic to detect relevant files
isPlinthFile :: T.Text -> Bool
isPlinthFile content = 
    "Plutus" `T.isInfixOf` content || 
    "Ledger" `T.isInfixOf` content || 
    "Validator" `T.isInfixOf` content

-- | Robust error handling
handleError :: FilePath -> CodexError -> IO ()
handleError file err = do
    let msg = case err of
            NetworkError e -> toText $ displayException e
            ApiError code  -> "API returned status code: " <> show code
            JsonError e    -> "Failed to parse JSON response: " <> toText e
    errorMessage $ "Failed to analyze " <> toText file <> ": " <> msg

getPlutusFiles :: FilePath -> IO [FilePath]
getPlutusFiles dir = do
    files <- getDirRecursive dir
    return $ filter (".hs" `isSuffixOf`) files

-- | Explicit Error Types
data CodexError 
    = NetworkError HttpException 
    | ApiError Int 
    | JsonError String
    deriving stock (Show)

-- | Gemini API Client
callGemini :: String -> T.Text -> IO (Either CodexError (Maybe String))
callGemini key code = do
    initialReq <- parseRequest $ "POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" ++ key
    let prompt = "Analyze this Haskell/Plutus code (specifically using the 'Plinth' framework) for security vulnerabilities, logic errors, and anti-patterns. Focus on validator logic and improper Plinth usage. Be concise. Logic: \n" <> code
    let payload = GeminiRequest { contents = [ GeminiContent { parts = [ GeminiPart { text = prompt } ] } ] }
    
    let req = setRequestBodyJSON payload 
            $ setRequestHeaders [("Content-Type", "application/json")] initialReq

    -- Catch network exceptions
    result <- try (httpLBS req)
    case result of
        Left (e :: HttpException) -> return $ Left (NetworkError e)
        Right resp -> do
            let status = getResponseStatusCode resp
            if status == 200
                then do
                    let body = getResponseBody resp
                    case Aeson.decode body :: Maybe GeminiResponse of
                        Just (GeminiResponse (c:_)) -> do
                            let partsList = parts (content c)
                            let combinedText = T.concat (map text partsList)
                            if T.null combinedText 
                                then return (Right Nothing) 
                                else return (Right $ Just $ toString combinedText)
                        _ -> return $ Left (JsonError "Invalid JSON structure or no candidates")
                else return $ Left (ApiError status)

-- | JSON Data Structures
newtype GeminiRequest = GeminiRequest { contents :: [GeminiContent] } deriving stock (Show, Eq, Generic)
instance ToJSON GeminiRequest

newtype GeminiContent = GeminiContent { parts :: [GeminiPart] } deriving stock (Show, Eq, Generic)
instance ToJSON GeminiContent

newtype GeminiPart = GeminiPart { text :: T.Text } deriving stock (Show, Eq, Generic)
instance ToJSON GeminiPart

newtype GeminiResponse = GeminiResponse { candidates :: [GeminiCandidate] } deriving stock (Show, Eq, Generic)
instance FromJSON GeminiResponse

newtype GeminiCandidate = GeminiCandidate { content :: GeminiContent } deriving stock (Show, Eq, Generic)
instance FromJSON GeminiCandidate

instance FromJSON GeminiContent where
    parseJSON = withObject "GeminiContent" $ \v -> GeminiContent
        <$> v .: "parts"

instance FromJSON GeminiPart where
    parseJSON = withObject "GeminiPart" $ \v -> GeminiPart
        <$> v .: "text"


