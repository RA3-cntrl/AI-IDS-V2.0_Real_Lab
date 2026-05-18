import pickle 
m = pickle.load(open('ids_binary_model.pkl','rb')) 
print('Features:', list(m.feature_names_in_)) 
print('Classes:', list(m.classes_)) 
