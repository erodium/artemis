import sklearn.metrics as metrics
import numpy as np
import itertools

import matplotlib 
import matplotlib.pyplot as plt


def get_metrics_XGB(df,model,label, opt_thresh=0.5,K=25):
    
    labels,prob,pred= df_info_XGB(df,model,label)
    
    thrs = np.linspace(0,1,K)
    
    #(tn,fp,fn,tp)
    cms = [metrics.confusion_matrix(labels, (prob > thr)*1) for thr in thrs]
    
    #Metric against threshold
    f1 = np.array([metrics.f1_score(labels, (prob > thr)*1) for thr in thrs])
    pre = np.array([metrics.precision_score(labels, (prob > thr)*1) for thr in thrs])
    rec = np.array([metrics.recall_score(labels, (prob > thr)*1) for thr in thrs])

    #Get Curves
    roc = metrics.roc_curve(labels, prob)
    pr = metrics.precision_recall_curve(labels, prob)
    auc = metrics.roc_auc_score(labels,prob)
    avgpr = metrics.average_precision_score(labels, prob)
    
    #Normalized Confusion Matrix
    #(tn,fp,fn,tp)
    cm = metrics.confusion_matrix(labels, [x > opt_thresh for x in prob])
    #cm = cm.astype('float')/cm.sum(axis=1)[:,np.newaxis]
    
    return cm, cms, roc, auc, pr, avgpr, pre, rec, f1, thrs



def df_info_XGB(df,model,label):
    temp=model.predict_proba(df)
    labels, prob, pred = label, [pr[1] for pr in temp], [round(pr[1]) for pr in temp]
    
    return labels, prob, pred

def print_summary_XGB(df,model,label,summary=None):
    
    labels, prob, pred = df_info_XGB(df,model,label)
    print('done with df_info retrieval')
    #Get an Optimal Threshold based on minimizing the tpr and fpr difference (for now)
    fpr, tpr, thresh = metrics.roc_curve(labels,prob)
    opt_thresh= thresh[np.argmax(tpr-fpr)]
    
    #extract_info_from_df
    print("#"*30)
    print("#"+ "Training".center(28, ' ')+"#")
    print("#"*30)
    if summary is not None:
        print("{0:20s}:\t{1:>6d}".format('Iterations',summary.totalIterations))
        print("{0:20s}:\t{1:>5.4f}".format('Area UnderROC',summary.areaUnderROC))
    print("{0:20s}:\t{1:>5.4f}".format('Optimal Threshold',opt_thresh))
    print("{0:20s}:\t{1:>5.4f}".format('Accuracy',metrics.accuracy_score(labels,(prob>opt_thresh)*1)))
    print("{0:20s}:\t{1:>5.4f}".format('Precision',metrics.precision_score(labels,(prob>opt_thresh)*1)))
    print("{0:20s}:\t{1:>5.4f}".format('Recall',metrics.recall_score(labels,(prob>opt_thresh)*1)))
    print("#"*30)
    return opt_thresh


def plot_curves_XGB(df_test,model, label,opt_thresh=None):
    
    matplotlib.style.use('seaborn-notebook')
    
    if opt_thresh is None:
        opt_thresh= 0.5
    
    #Get test metrics to plot
    cm,cms,roc,auc,pr,avgpr,precision,recall,f1,thrs=get_metrics_XGB(df_test,model,label,opt_thresh,K=25)
    print('done with get metrics')
    #Subplots
    fig, ax = plt.subplots(2,3,figsize=(15,8.4))
    plt.subplots_adjust(hspace=0.4)
    ax1,ax2,ax3,ax4,ax5,ax6=ax[0,0], ax[0,1], ax[0,2], ax[1,0], ax[1,1], ax[1,2]
    
    #ROC Curve
    ax1.step(roc[0], roc[1], ".:", color='#61b0f4')
    ax1.plot([0,1],[0,1],"k:")
    ax1.set_ylabel('TPR (Recall)')
    ax1.set_xlabel('FPR')
    ax1.legend(loc='lower right')
    ax1.set_title('ROC Curve - AUC: {0:1.4f}'.format(auc))
    
    #PR Curve
    ax2.step(pr[1], pr[0], color='#61b0f4', where = 'post')
    ax2.fill_between(pr[1], pr[0], step='post', alpha=0.2, color ='#61b0f4')
    ax2.set_ylabel('Precision')
    ax2.set_xlabel('Recall')
    ax2.legend(loc='lower right')
    ax2.set_title('PR Curve - Avg. Pr: {0:1.4f}'.format(avgpr))  
    
    #Confusion Matrix
    thresh=cm.max() / 2.
    tick_marks = np.arange(2)
    ax3.imshow(cm, interpolation='nearest',cmap=plt.cm.Blues)
    ax3.set_xticks(np.arange(2), minor=False)
    ax3.set_yticks(np.arange(2), minor=False)
    ax3.set_xticklabels(['not fraud', 'fraud'], fontdict=None, minor=False)
    ax3.set_yticklabels(['not fraud', 'fraud'], fontdict=None, minor=False)
    #ax3.xticks(tick_marks, ['not fraud', 'fraud'])
    #ax3.yticks(tick_marks, ['not fraud', 'fraud'])
    
    ax3.set_title('Confusion Matrix - {0:s} Threshold: {1:1.3f}'.format("" if opt_thresh == 0.5 else 'Optimal', opt_thresh))
     #(tn,fp,fn,tp)
    #print(cm[i,j])
    for i,j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        ax3.text(j, i, format(cm[i, j], ".0f"),
                horizontalalignment='center',
                color='white' if cm[i,j] > thresh else "black")
    ax3.set_ylabel("True Label")
    ax3.set_xlabel("Predicted Label")
    
    
    # Precision THR Curve
    ax4.plot(thrs, precision, ".:", color = '#61b0f4')
    ax4.set_ylabel('Precision')
    ax4.set_xlabel('Threshold')
    ax4.set_ylim([0.0,1.0])
    ax4.set_xlim([0.0,1.0])
    ax4.set_title('Precision Threshold Curve')
    
    # Recall THR Curve
    ax5.plot(thrs, recall, ".:", color = '#61b0f4')
    ax5.set_ylabel('Recall')
    ax5.set_xlabel('Threshold')
    ax5.set_ylim([0.0,1.0])
    ax5.set_xlim([0.0,1.0])
    ax5.set_title('Recall Threshold Curve')
    
    # f1 THR Curve
    ax6.plot(thrs, f1, ".:", color = '#61b0f4')
    ax6.set_ylabel('f1')
    ax6.set_xlabel('Threshold')
    ax6.set_ylim([0.0,1.0])
    ax6.set_xlim([0.0,1.0])
    ax6.set_title('F1 Threshold Curve')
    
    return cms