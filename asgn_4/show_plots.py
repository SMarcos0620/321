import matplotlib.pyplot as plt
import polars

df = polars.read_csv("out1.csv")

bits = df["Bit Size"]
collision_time = df["Time (s)"]

plt.figure(1, figsize=(5, 5))
plt.plot(bits, collision_time)
plt.xlabel("Digest Size (bits)")
plt.ylabel("Collision Time")
plt.title("Digest Size vs Collision Time")
plt.savefig("Digest_Size_vs_Collision_Time.jpg")


inputs = df["Tries"]

plt.figure(2, figsize=(5, 5))
plt.plot(bits, inputs)
plt.xlabel("Digest Size (bits)")
plt.ylabel("Number of Inputs")
plt.title("Digest Size vs Number of Inputs")
plt.savefig("Digest_Size_vs_Number_of_Inputs.jpg")

plt.show()
