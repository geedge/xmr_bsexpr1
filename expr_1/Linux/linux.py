import os
import numpy as np
import matplotlib.pyplot as plt
import scipy.linalg as la
from scipy import optimize
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression

class FitNonlinearLeastSquares(object):

    def fit_func(self, data_x, data_y):
        p0 = np.random.rand(2)
        fit_res = optimize.least_squares(self.error, p0,
                                         args=(data_x, data_y))
                                        #   bounds=((0, 0), (1000, np.inf)))
        fit_res = dict(fit_res)
        print(fit_res)
        return fit_res

    @staticmethod
    def func(p, x):
        """
        Define the form of fitting function.
        """
        k, b = p
        return k * x + b

    def error(self, p, x, y):
        """
        Fitting residuals.
        """
        return y - self.func(p, x)

    def mapping(self, fit_res, data_x, data_y):
        y_fitted = self.func(fit_res['x'], data_x)
        plt.plot(data_x, data_y, 'o', label='Data')
        plt.plot(data_x, y_fitted, label='Fitted curve')
        plt.xlabel('x')
        plt.ylabel('y')
        plt.legend()
        plt.savefig('test_fit.jpg')
        # plt.show()
        plt.pause(0.5)
        plt.close()

    def main(self, data_x, data_y):
        fit_res = self.fit_func(data_x, data_y)
        self.mapping(fit_res, data_x, data_y)
        return fit_res['x']

def Fun(x, a, b):
    return a * x + b

if __name__ == "__main__":

    dstIP_srcIP_dict = {}
    dstIP_rt_dict = {}
    dstIP_tv_dict = {}

    with open("/home/xmr/Doc/expr_1/Linux/Linux_two.txt", "r") as f:
        lines = f.readlines()

        for line in lines:
            line = line.strip()
            items = str.split(line, " ")

            # min_time = min(min_time, float(items[0]))

            if items[1] != "TCP":
                continue

            if items[2] != "....S.":
                continue

            host_ip_1 = "192.168.47.183"  
            host_ip_2 = "192.168.47.231"

            if ((items[3] != host_ip_1) and (items[3] != host_ip_2)): # 只需要向外发出的流量, linux
                continue
            
            # if ((items[3] != host_ip_2)): # 只需要向外发出的流量, linux
            #     continue

            if items[4] not in dstIP_srcIP_dict:
                dstIP_srcIP_dict[items[4]] = set()
                dstIP_rt_dict[items[4]] = []
                dstIP_tv_dict[items[4]] = []

            dstIP_srcIP_dict[items[4]].add( items[3] )
            dstIP_rt_dict[items[4]].append( float(items[0]) )
            dstIP_tv_dict[items[4]].append( float((items[9])) )

    alpha_list = []
    sorce_list = []

    for dst_ip in dstIP_srcIP_dict.keys():
        if len( dstIP_rt_dict[dst_ip] ) < 10:
            continue
        print( dst_ip )


        print( dstIP_rt_dict[dst_ip] )
        print( dstIP_tv_dict[dst_ip] )

        X = dstIP_rt_dict[dst_ip]
        Y = dstIP_tv_dict[dst_ip]

        X_train = np.array(X).reshape((len(X), 1))
        Y_train = np.array(Y).reshape((len(Y), 1))

        model = LinearRegression()
        model.fit(X_train, Y_train)

        #用训练后的模型，进行预测
        Y_predict = model.predict(X_train)
    
        #coef_是系数，intercept_是截距
        a1 = model.coef_[0][0]
        b = model.intercept_[0]
        print("y=%.4f*x+%.4f" % (a1,b))
        print("得分", model.score(X_train, Y_train))

        alpha_list.append(a1)
        sorce_list.append(model.score(X_train, Y_train))

        
        #简单画图显示
        plt.scatter(X, Y, c="blue")
        plt.plot(X_train,Y_predict, c="red")
        
        plt.xlabel('Time')

        plt.ylabel('Tcp TimeStamp')

        
        # plt.legend(loc="right",numpoints=1,labels=['host_1'], fontsize=10)

        # matplotlib.rc("font",family='MicroSoft YaHei',weight="bold")
        # plt.figure(dpi=100)
        plt.rcParams['savefig.dpi'] = 900 #图片像素
        plt.rcParams['figure.dpi'] = 300 #分辨率
    
        # plt.show()

        plt.savefig('test_fit.jpg')
        # plt.show()
        plt.pause(0.5)
        plt.close()

    print( len(alpha_list) )

    arr = alpha_list
    #求均值
    arr_mean = np.mean(arr)
    #求方差
    arr_var = np.var(arr)
    #求标准差
    arr_std = np.std(arr,ddof=1)
    #求最值
    arr_New = sorted(arr)
    arr_Min = arr_New[0]
    arr_Max = arr_New[len(arr_New)-1]
    print("平均值为：%f" % arr_mean)
    print("方差为：%f" % arr_var)
    print("标准差为:%f" % arr_std)
    print("最小值是：",arr_Min)
    print("最大值是：",arr_Max)

    arr = sorce_list
    #求均值
    arr_mean = np.mean(arr)
    #求方差
    arr_var = np.var(arr)
    #求标准差
    arr_std = np.std(arr,ddof=1)
    #求最值
    arr_New = sorted(arr)
    arr_Min = arr_New[0]
    arr_Max = arr_New[len(arr_New)-1]
    print("平均值为：%f" % arr_mean)
    print("方差为：%f" % arr_var)
    print("标准差为:%f" % arr_std)
    print("最小值是：",arr_Min)
    print("最大值是：",arr_Max)


