import pickle
import pandas
from sklearn.preprocessing import LabelEncoder
from timeit import default_timer as timer
import datetime
def MLP(): #For training either a new model or updating a previous model

            l_data = input("Name of CSV file? ") 
            
            load = input("Load model? y/n ") #use saved model or train new one
            if load == 'y':
                mlp = Load_model()
                return Predict(mlp, l_data)

            else:
                from sklearn.neural_network import MLPClassifier #imports the neural network class from Sci-kit learn
                mlp = MLPClassifier(solver='sgd',hidden_layer_sizes=(10,10),activation='logistic', max_iter=100, verbose=True, tol=0.00000001, early_stopping = True, shuffle = True) # Designates the setting of the model before training
                #hidden_layer_sizes = array of the hidden layer of the network, (5) = one layer of 5 nodes, (5,5) = 2 layers, both with 5 nodes
                #activation = activation function, 'logistic' is equivalent ot the sigmoid activation function
                #max_iter = max3imum amoung of iterations that the model will do
                #Verbose = whether the model prints the iteration and loss function per iteration
                #tol = the decimal place the use wants the loss function to reach
                from sklearn.model_selection import train_test_split #Needed to split the data into the training and testing
                from sklearn.preprocessing import StandardScaler #required to so that all the inputs are in a comparable range
                data = pandas.read_csv(l_data, delimiter=',')# read CSV
                data = LabelEncoding(data)
                X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port','Packet Length', 'Packets/Time']] # Data used to train
            
                y = data['target']
                X_train, X_test, y_train, y_test = train_test_split(X, y)
            
                start_time = timer()
                mlp.fit(X_train, y_train) #training
                end_time = timer()
                time_taken = end_time - start_time
                print('Training time ',time_taken)
                predictions = mlp.predict(X_test)
                hostile = 0
                safe = 0
                for check in predictions:
                    if check == 1:
                        hostile += 1
                    else:
                        safe += 1
                print("Safe Packets: ", safe)
                print("Hostile Packets: ", hostile)
                if (hostile >= (safe/2)):
                    with open('log.txt','r+') as testwrite:
                        testwrite.write('Attack Detected at: ')
                        testwrite.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
                        testwrite.write('\n')
                        testwrite.write('Packets collected: ')
                        testwrite.write(str(safe + hostile))
                        testwrite.write('\n')
                    with open('log.txt','w') as testwrite:
                        for line in testwrite:
                            print(line)
                save = input("Save model? ")
                if save == 'y':
                    filename = input("Filename for saving?: ")
                    pickle.dump(mlp, open(filename, 'wb'))
                 
                        

def LabelEncoding(data): # turns the categorical values into integer values

        data = pandas.read_csv('TestingData.csv', delimiter=',')
        columnsToEncode = list(data.select_dtypes(include=['category', 'object']))  
      
        
        le = LabelEncoder()
        for feature in columnsToEncode:
            try:
                data[feature] = le.fit_transform(data[feature])
               
            except:
                print ('error' + feature)
        return data

def Load_model(): # loads a saved model to use for both training 

            filename = input("Model to load? ")
            loaded_model = pickle.load(open(filename, 'rb'))
                        
            return loaded_model
        
def Predict(mlp, l_data):
    data = pandas.read_csv(l_data, delimiter=',')# reads CSV
    data = LabelEncoding(data)
    X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port','Packet Length', 'Packets/Time']]
    y = data['target']
    predictions = mlp.predict(X)
   
    print()
    print()
    hostile = 0
    safe = 0
    for check in predictions:
        if check == 1:
            hostile += 1
        else:
            safe += 1
    print("Safe Packets: ", safe)
    print("Hostile Packets: ", hostile)
    if (hostile >= (hostile+safe)/2):
        with open('log.txt','rw') as testwrite:
            testwrite.write('Attack Detected at: ')
            testwrite.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
            testwrite.write('\n')
            testwrite.write('Packets collected: ')
            testwrite.write(str(safe + hostile))
            testwrite.write('\n')
            for line in testwrite:
                print(line)
    from sklearn.metrics import classification_report,confusion_matrix
    print("Confusion Matrix: ", "\n", confusion_matrix(y,predictions))
    print()

    print ("Classification Report: ", "\n",  classification_report(y,predictions))
    print()

    ci = input("do you want to see weights and intercepts? " )
    if ci == 'y':
        print("Model Coefficients (Weights): ", "\n", mlp.coefs_)
        print()
        print("Model Intercepts (Nodes): ", "\n", mlp.intercepts_)
    else:
        pass

MLP()
