package crypto;
import javax.swing.*;
import java.awt.*;

public class rsaa extends JFrame {
    private static final long serialVersionUID = 1L;
    private JPanel aesPanel;
    private JPanel rsaPanel;
    private JTabbedPane tabbedPane;
    private JButton aesEncryptButton;
    private JButton aesDecryptButton;
    private JButton rsaEncryptButton;
    private JButton rsaDecryptButton;
    private JTextArea aesInputTextArea;
    private JTextArea aesOutputTextArea;
    private JTextArea rsaInputTextArea;
    private JTextArea rsaOutputTextArea;
    private JTextField rsaPublicKeyField;
    private JTextField rsaPrivateKeyField;
    private JButton generateKeysButton;

    public rsaa() throws HeadlessException {
        setTitle("Encryption / Decryption");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 500);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        createAesPanel();
        createRsaPanel();

        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("AES", aesPanel);
        tabbedPane.addTab("RSA", rsaPanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    private void createAesPanel() {
        aesPanel = new JPanel();
        aesPanel.setLayout(new BorderLayout());

        aesInputTextArea = new JTextArea();
        aesOutputTextArea = new JTextArea();
        aesOutputTextArea.setEditable(false);

        JScrollPane inputScrollPane = new JScrollPane(aesInputTextArea);
        JScrollPane outputScrollPane = new JScrollPane(aesOutputTextArea);

        JPanel buttonPanel = new JPanel();
        aesEncryptButton = new JButton("Encrypt");
        aesDecryptButton = new JButton("Decrypt");
        buttonPanel.add(aesEncryptButton);
        buttonPanel.add(aesDecryptButton);

        aesPanel.add(inputScrollPane, BorderLayout.CENTER);
        aesPanel.add(outputScrollPane, BorderLayout.SOUTH);
        aesPanel.add(buttonPanel, BorderLayout.NORTH);
    }

    private void createRsaPanel() {
        rsaPanel = new JPanel();
        rsaPanel.setLayout(new BorderLayout());

        rsaInputTextArea = new JTextArea();
        rsaOutputTextArea = new JTextArea();
        rsaOutputTextArea.setEditable(false);

        JScrollPane inputScrollPane = new JScrollPane(rsaInputTextArea);
        JScrollPane outputScrollPane = new JScrollPane(rsaOutputTextArea);

        JPanel keyPanel = new JPanel(new GridLayout(2, 1));

        JPanel publicKeyPanel = new JPanel(new BorderLayout());
        JLabel publicKeyLabel = new JLabel("Public Key:");
        rsaPublicKeyField = new JTextField();
        rsaPublicKeyField.setEditable(false);
        publicKeyPanel.add(publicKeyLabel, BorderLayout.WEST);
        publicKeyPanel.add(rsaPublicKeyField, BorderLayout.CENTER);

        JPanel privateKeyPanel = new JPanel(new BorderLayout());
        JLabel privateKeyLabel = new JLabel("Private Key:");
        rsaPrivateKeyField = new JTextField();
        rsaPrivateKeyField.setEditable(false);
        privateKeyPanel.add(privateKeyLabel, BorderLayout.WEST);
        privateKeyPanel.add(rsaPrivateKeyField, BorderLayout.CENTER);

        keyPanel.add(publicKeyPanel);
        keyPanel.add(privateKeyPanel);

        JPanel buttonPanel = new JPanel();
        rsaEncryptButton = new JButton("Encrypt");
        rsaDecryptButton = new JButton("Decrypt");
        generateKeysButton = new JButton("Generate Keys");
        buttonPanel.add(rsaEncryptButton);
        buttonPanel.add(rsaDecryptButton);
        buttonPanel.add(generateKeysButton);

        rsaPanel.add(inputScrollPane, BorderLayout.CENTER);
        rsaPanel.add(outputScrollPane, BorderLayout.SOUTH);
        rsaPanel.add(keyPanel, BorderLayout.NORTH);
        rsaPanel.add(buttonPanel, BorderLayout.SOUTH);
    }

    public JButton getAesEncryptButton() {
        return aesEncryptButton;
    }

    public JButton getAesDecryptButton() {
        return aesDecryptButton;
    }

    public JButton getRsaEncryptButton() {
        return rsaEncryptButton;
    }

    public JButton getRsaDecryptButton() {
        return rsaDecryptButton;
    }

    public JButton getGenerateKeysButton() {
        return generateKeysButton;
    }

    public JTextArea getAesInputTextArea() {
        return aesInputTextArea;
    }

    public JTextArea getAesOutputTextArea() {
        return aesOutputTextArea;
    }

    public JTextArea getRsaInputTextArea() {
        return rsaInputTextArea;
    }

    public JTextArea getRsaOutputTextArea() {
        return rsaOutputTextArea;
    }

    public JTextField getRsaPublicKeyField() {
        return rsaPublicKeyField;
    }

    public JTextField getRsaPrivateKeyField() {
        return rsaPrivateKeyField;
    }
}