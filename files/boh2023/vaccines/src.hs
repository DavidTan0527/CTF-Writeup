import System.IO
import System.Exit
import System.Random -- cabal install random
import System.Random.Mersenne.Pure64 -- cabal install mersenne-random-pure64
import Data.Time.Clock.POSIX (getPOSIXTime)

data Vaccine = Vaccine {
    num :: Int,
    description :: String,
    date :: String
} deriving Show

printVaccine :: Vaccine -> IO ()
printVaccine vaccine = do
    putStrLn $ "Vaccine ID: " ++ (show $ num vaccine)
    putStrLn $ "Vaccine Description: " ++ (description vaccine)
    putStrLn $ "Vaccine Date: " ++ (date vaccine)

editVaccine:: Vaccine -> IO Vaccine
editVaccine vaccine = do
    putStrLn "Enter new Vaccine description: "
    newDescription <- getLine
    putStrLn "Enter new Vaccine date: "
    newDate <- getLine
    return $ Vaccine (num vaccine) newDescription newDate

strlen :: String -> Int
strlen input = Prelude.length $ Prelude.takeWhile (/= '\0') input

atoi :: String -> Int
atoi input = do
    let input' = Prelude.filter (\x -> x >= '0' && x <= '9') input
    Prelude.read input' :: Int

main = do
    hSetBuffering stdin NoBuffering -- disable buffering from STDIN
    hSetBuffering stdout NoBuffering -- disable buffering from STDOUT
    hSetBuffering stderr NoBuffering -- disable buffering from STDERR
    

    -- Init random generator
    flag <- readFile "flag.txt"
    time <- (round . (* 1)) <$> getPOSIXTime
    let seed = fromInteger(time*1000)
    let g = pureMT seed
    let (num, _) = randomR (10, 100) g :: (Int, PureMT)
    let vaccines = [Vaccine x "some random Vaccine" "03/04/2020" | x <- [0..num]] ++ [Vaccine (num+1) flag "03/04/2020"]

    let loop = do
            putStrLn "What do you want to do?"
            putStrLn "1. View Vaccine"
            putStrLn "2. Edit Vaccine"
            putStrLn "3. Exit"
            choice <- getLine
            case choice of
                "1" -> do
                    putStrLn "Enter Vaccine ID: "
                    input <- getLine
                    if (strlen input == 1 && input !! 0 /= '0') then do
                        let id = atoi input
                        if (id >= 0 && id < Prelude.length vaccines) then do
                            printVaccine $ vaccines !! id
                            loop
                        else do
                            print ("Invalid Vaccine ID, we only have " ++ (show $ Prelude.length vaccines) ++ " vaccines")
                            loop
                    else do
                        putStrLn "Invalid Vaccine ID"
                        loop
                "2" -> do
                    putStrLn "Enter Vaccine ID: "
                    input <- getLine
                    if (strlen input == 1 && input !! 0 /= '0') then do
                        let id = atoi input
                        if (id >= 0 && id < Prelude.length vaccines) then do
                            newVaccine <- editVaccine $ vaccines !! id
                            let vaccines' = Prelude.take id vaccines ++ [newVaccine] ++ Prelude.drop (id+1) vaccines
                            printVaccine $ vaccines' !! id
                            loop
                        else do
                            print ("Invalid Vaccine ID, we only have " ++ (show $ Prelude.length vaccines) ++ " vaccines")
                            loop
                    else do
                        putStrLn "Invalid Vaccine ID"
                        loop
                "3" -> do
                    putStrLn "Bye!"
                    exitSuccess                    
                _ -> do
                    putStrLn "Invalid choice"
                    loop
    loop
