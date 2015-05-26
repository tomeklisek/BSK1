/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1;

/**
 *
 * @author bln
 */
public class Log {
    public static javax.swing.JTextArea jTextArea;
    
    public static void setTextArea(javax.swing.JTextArea textArea) {
        jTextArea = textArea;
    }
    
    public static void writeLine(String text) {
        jTextArea.append(text+"\n");
    }
    
    public static void writeLine(int number) {
        jTextArea.append(Integer.toString(number)+"\n");
    }
}
