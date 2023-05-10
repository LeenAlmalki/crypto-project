package crypto;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import java.awt.Color;
import javax.swing.JTextPane;
import javax.swing.JTextField;
import javax.swing.JLabel;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.border.EtchedBorder;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import net.miginfocom.swing.MigLayout;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;

public class cryptotool {

	private JFrame frame;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					cryptotool window = new cryptotool();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public cryptotool() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 506, 556);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		frame.getContentPane().add(tabbedPane, BorderLayout.NORTH);
		
		JPanel rsa = new JPanel();
		tabbedPane.addTab("RSA", null, rsa, null);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Settings", TitledBorder.LEFT, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JPanel panel_1_1 = new JPanel();
		panel_1_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Encrypt / Decrypt", TitledBorder.LEFT, TitledBorder.TOP, null, Color.BLACK));
		GroupLayout gl_rsa = new GroupLayout(rsa);
		gl_rsa.setHorizontalGroup(
			gl_rsa.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_rsa.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_rsa.createParallelGroup(Alignment.TRAILING)
						.addComponent(panel_1_1, Alignment.LEADING, 0, 0, Short.MAX_VALUE)
						.addComponent(panel_2, Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 467, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(10, Short.MAX_VALUE))
		);
		gl_rsa.setVerticalGroup(
			gl_rsa.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_rsa.createSequentialGroup()
					.addContainerGap()
					.addComponent(panel_2, GroupLayout.PREFERRED_SIZE, 219, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_1_1, GroupLayout.PREFERRED_SIZE, 254, Short.MAX_VALUE)
					.addContainerGap())
		);
		
		JLabel lblNewLabel_2 = new JLabel("Cipher / Plain Text");
		
		JTextArea input = new JTextArea();
		
		JButton encrypt_rsa_button = new JButton("Encrypt");
		encrypt_rsa_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		
		JButton decrypt_rsa_button = new JButton("Decrypt");
		decrypt_rsa_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		
		JButton Clear = new JButton("Clear");
		Clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		
		JLabel lblNewLabel_3 = new JLabel("Output");
		
		JTextArea output_rsa = new JTextArea();
		GroupLayout gl_panel_1_1 = new GroupLayout(panel_1_1);
		gl_panel_1_1.setHorizontalGroup(
			gl_panel_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1.createSequentialGroup()
					.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(input, GroupLayout.DEFAULT_SIZE, 435, Short.MAX_VALUE))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addGap(184)
							.addComponent(Clear))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
								.addComponent(output_rsa, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE)
								.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
									.addComponent(lblNewLabel_2)
									.addGroup(gl_panel_1_1.createSequentialGroup()
										.addComponent(lblNewLabel_3, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(ComponentPlacement.RELATED, 98, Short.MAX_VALUE)
										.addComponent(encrypt_rsa_button)
										.addGap(18)
										.addComponent(decrypt_rsa_button)
										.addGap(140))))))
					.addContainerGap())
		);
		gl_panel_1_1.setVerticalGroup(
			gl_panel_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_2)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(input, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addGap(18)
							.addComponent(lblNewLabel_3))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addGroup(gl_panel_1_1.createParallelGroup(Alignment.BASELINE)
								.addComponent(encrypt_rsa_button)
								.addComponent(decrypt_rsa_button))))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(output_rsa, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(Clear)
					.addGap(25))
		);
		panel_1_1.setLayout(gl_panel_1_1);
		
		JLabel lblNewLabel = new JLabel("Private Key");
		
		JLabel lblNewLabel_1 = new JLabel("Public Key");
		
		JButton generate = new JButton("Generate Key Pairs");
		
		JButton clear_settings1 = new JButton("Clear");
		
		JTextArea privatekey_input = new JTextArea();
		
		JTextArea publickey_input = new JTextArea();
		
		JScrollPane scrollPane = new JScrollPane();
		GroupLayout gl_panel_2 = new GroupLayout(panel_2);
		gl_panel_2.setHorizontalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup()
					.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_2.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
								.addComponent(lblNewLabel_1, GroupLayout.PREFERRED_SIZE, 62, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel))
							.addGap(10)
							.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
								.addComponent(publickey_input, GroupLayout.DEFAULT_SIZE, 363, Short.MAX_VALUE)
								.addComponent(privatekey_input, GroupLayout.DEFAULT_SIZE, 363, Short.MAX_VALUE)))
						.addGroup(gl_panel_2.createSequentialGroup()
							.addGap(100)
							.addComponent(generate)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(clear_settings1, GroupLayout.PREFERRED_SIZE, 114, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap())
		);
		gl_panel_2.setVerticalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup()
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.TRAILING, false)
						.addGroup(gl_panel_2.createSequentialGroup()
							.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
								.addComponent(lblNewLabel)
								.addComponent(privatekey_input, GroupLayout.PREFERRED_SIZE, 54, GroupLayout.PREFERRED_SIZE))
							.addGap(12))
						.addGroup(gl_panel_2.createSequentialGroup()
							.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addGap(35)))
					.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblNewLabel_1)
						.addComponent(publickey_input, GroupLayout.PREFERRED_SIZE, 54, GroupLayout.PREFERRED_SIZE))
					.addGap(26)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
						.addComponent(generate)
						.addComponent(clear_settings1))
					.addGap(30))
		);
		panel_2.setLayout(gl_panel_2);
		rsa.setLayout(gl_rsa);
		
		JPanel aes = new JPanel();
		tabbedPane.addTab(" AES", null, aes, null);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Settings", TitledBorder.LEFT, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JPanel panel_1_1_1 = new JPanel();
		panel_1_1_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Encrypt / Decrypt", TitledBorder.LEFT, TitledBorder.TOP, null, Color.BLACK));
		
		JTextArea input_aes = new JTextArea();
		
		JButton Clear_1 = new JButton("Clear");
		
		JTextArea output_aes = new JTextArea();
		
		JLabel lblNewLabel_2_1 = new JLabel("Cipher / Plain Text");
		
		JLabel lblNewLabel_3_1 = new JLabel("Output");
		
		JButton encrypt_aes_button = new JButton("Encrypt");
		
		JButton decrypt_aes_button = new JButton("Decrypt");
		decrypt_aes_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			}
		});
		GroupLayout gl_panel_1_1_1 = new GroupLayout(panel_1_1_1);
		gl_panel_1_1_1.setHorizontalGroup(
			gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
				.addGap(0, 467, Short.MAX_VALUE)
				.addGroup(gl_panel_1_1_1.createSequentialGroup()
					.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(input_aes, GroupLayout.DEFAULT_SIZE, 435, Short.MAX_VALUE))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addGap(184)
							.addComponent(Clear_1))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
								.addComponent(output_aes, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel_2_1)
								.addGroup(gl_panel_1_1_1.createSequentialGroup()
									.addComponent(lblNewLabel_3_1, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED, 98, Short.MAX_VALUE)
									.addComponent(encrypt_aes_button)
									.addGap(18)
									.addComponent(decrypt_aes_button)
									.addGap(140)))))
					.addContainerGap())
		);
		gl_panel_1_1_1.setVerticalGroup(
			gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
				.addGap(0, 254, Short.MAX_VALUE)
				.addGroup(gl_panel_1_1_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_2_1)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(input_aes, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addGap(18)
							.addComponent(lblNewLabel_3_1))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.BASELINE)
								.addComponent(encrypt_aes_button)
								.addComponent(decrypt_aes_button))))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(output_aes, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(Clear_1)
					.addGap(25))
		);
		panel_1_1_1.setLayout(gl_panel_1_1_1);
		GroupLayout gl_aes = new GroupLayout(aes);
		gl_aes.setHorizontalGroup(
			gl_aes.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_aes.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_aes.createParallelGroup(Alignment.LEADING)
						.addComponent(panel, GroupLayout.DEFAULT_SIZE, 467, Short.MAX_VALUE)
						.addComponent(panel_1_1_1, GroupLayout.PREFERRED_SIZE, 467, GroupLayout.PREFERRED_SIZE))
					.addContainerGap())
		);
		gl_aes.setVerticalGroup(
			gl_aes.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_aes.createSequentialGroup()
					.addGap(12)
					.addComponent(panel, GroupLayout.PREFERRED_SIZE, 219, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_1_1_1, GroupLayout.PREFERRED_SIZE, 254, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
		);
		
		JLabel lblNewLabel_4 = new JLabel("Secret Key");
		
		JTextArea textArea = new JTextArea();
		
		JButton generate_aes_buton = new JButton("Generate Key");
		
		JButton btnNewButton = new JButton("Clear");
		GroupLayout gl_panel = new GroupLayout(panel);
		gl_panel.setHorizontalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_4)
					.addGap(28)
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(51)
							.addComponent(generate_aes_buton)
							.addGap(18)
							.addComponent(btnNewButton, GroupLayout.PREFERRED_SIZE, 88, GroupLayout.PREFERRED_SIZE))
						.addComponent(textArea, GroupLayout.PREFERRED_SIZE, 337, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(22, Short.MAX_VALUE))
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(22)
							.addComponent(textArea, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE))
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(39)
							.addComponent(lblNewLabel_4)))
					.addGap(48)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(generate_aes_buton)
						.addComponent(btnNewButton))
					.addContainerGap(69, Short.MAX_VALUE))
		);
		panel.setLayout(gl_panel);
		aes.setLayout(gl_aes);
	}
}
