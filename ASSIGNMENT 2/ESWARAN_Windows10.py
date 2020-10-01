#!/usr/bin/env python
# coding: utf-8

# In[53]:


import pandas as pd
import matplotlib.pyplot as plt


# In[54]:


df = pd.read_json(r'windows10.json', lines = True, orient = str) #Change it to Eswaran_windows10.json 
data
df.to_csv(r'windows10.csv')
data = pd.read_csv("windows10.csv")
data


# In[55]:


data.head()
dates = data["Published"]
months = []


# In[56]:


for date in dates:
    date, time = date.split()
    months.append(date)
    date = date.split("-")
    time = time.split(":")


# In[57]:


print(len(set(months)), len(months))


# In[58]:


unique_months = list(set(months))
counts = []
c = 0


# In[59]:


unique_months.sort()


# In[60]:


for i in unique_months:
    c+=months.count(i)
    counts.append(c)
print(unique_months)

plt.plot(unique_months, counts)
plt.xlabel("Date")
plt.ylabel("Repititions")
plt.show();

